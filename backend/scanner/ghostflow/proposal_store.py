from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .repair import validate_safe_path
from .repair_models import (
    AIAdvisoryMetadata,
    IntelligentRepairProposal,
    PatchHunk,
    ProposalApprovalState,
    ProposalFile,
    ProposalOrigin,
    ProposalVerificationPlan,
    ServerProposalRecord,
    TripartiteAnalysis,
)

PROP_ID_RE = re.compile(r"^prop_\d{8}_\d{6}_[a-f0-9]{8}$")
DEFAULT_PROPOSAL_TTL_SECONDS = 3600  # 1 hour


class ProposalStoreError(Exception):
    """Base exception for server proposal store operations."""
    pass


class ProposalNotFoundError(ProposalStoreError):
    """Raised when a proposal ID does not exist in the store."""
    pass


class ProposalExpiredError(ProposalStoreError):
    """Raised when an action is attempted on an expired proposal."""
    pass


class ProposalStaleError(ProposalStoreError):
    """Raised when target files have drifted since proposal generation."""
    pass


class ProposalAlreadyAppliedError(ProposalStoreError):
    """Raised when attempting to re-apply an already executed proposal."""
    pass


class ProposalTamperedError(ProposalStoreError):
    """Raised when a server proposal record has been tampered with or corrupted."""
    pass


class ProposalProjectMismatchError(ProposalStoreError):
    """Raised when a proposal is accessed from an mismatched project root."""
    pass


class ProposalLock:
    """Proposal-specific lock for atomic state transitions."""

    def __init__(self, project_root: Path, proposal_id: str, timeout: float = 10.0):
        self.project_root = project_root.expanduser().resolve()
        self.proposal_id = proposal_id
        self.timeout = timeout
        self.lock_dir = self.project_root / ".ghostflow" / "locks"
        self.lock_file = self.lock_dir / f"{proposal_id}.lock"
        self._fd: int | None = None

    def acquire(self) -> None:
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        start_time = time.time()
        while True:
            try:
                self._fd = os.open(
                    str(self.lock_file),
                    os.O_CREAT | os.O_EXCL | os.O_RDWR,
                    0o600,
                )
                payload = json.dumps({
                    "proposal_id": self.proposal_id,
                    "pid": os.getpid(),
                    "timestamp": time.time(),
                }).encode("utf-8")
                os.write(self._fd, payload)
                return
            except FileExistsError:
                try:
                    mtime = self.lock_file.stat().st_mtime
                    if time.time() - mtime > 30.0:
                        try:
                            self.lock_file.unlink(missing_ok=True)
                        except OSError:
                            pass
                except OSError:
                    pass

                if time.time() - start_time > self.timeout:
                    raise ProposalStoreError(
                        f"Could not acquire proposal lock for '{self.proposal_id}' after {self.timeout}s."
                    )
                time.sleep(0.05)

    def release(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        try:
            self.lock_file.unlink(missing_ok=True)
        except OSError:
            pass

    def __enter__(self) -> ProposalLock:
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class ServerProposalStore:
    """Manages secure, server-side storage and lifecycle of repair proposals."""

    _signing_key_lock: threading.Lock = threading.Lock()

    @staticmethod
    def generate_proposal_id() -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rand = uuid.uuid4().hex[:8]
        return f"prop_{timestamp}_{rand}"

    @classmethod
    def get_signing_key(cls) -> bytes:
        """Resolve persistent cryptographic HMAC secret.

        Order of precedence:
        1. Environment variable GHOSTFLOW_SIGNING_KEY.
        2. Persistent server secret file at Path.home() / ".ghostflow" / "server_secret.key".

        The key is never stored in the proposal record or any untrusted project directory.
        Fails safely if the key is empty, invalid, or cannot be securely read/created.
        """
        env_key = os.environ.get("GHOSTFLOW_SIGNING_KEY")
        if env_key is not None:
            cleaned = env_key.strip()
            if not cleaned or len(cleaned) < 16:
                raise ProposalStoreError("Invalid signing key: GHOSTFLOW_SIGNING_KEY must be at least 16 bytes.")
            return cleaned.encode("utf-8")

        with cls._signing_key_lock:
            home_gf = Path.home() / ".ghostflow"
            key_file = home_gf / "server_secret.key"

            try:
                home_gf.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ProposalStoreError(f"Failed to create secure key directory '{home_gf}': {e}")

            if key_file.exists():
                start_t = time.time()
                while time.time() - start_t < 5.0:
                    try:
                        key_bytes = key_file.read_bytes().strip()
                        if key_bytes and len(key_bytes) >= 16:
                            return key_bytes
                    except OSError:
                        pass
                    time.sleep(0.01)
                raise ProposalStoreError(f"Server signing key in '{key_file}' is invalid or corrupted.")

            new_key = secrets.token_hex(32).encode("utf-8")
            try:
                fd = os.open(str(key_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(new_key)
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    os.chmod(key_file, 0o600)
                except OSError:
                    pass
                return new_key
            except FileExistsError:
                start_t = time.time()
                while time.time() - start_t < 5.0:
                    try:
                        if key_file.exists():
                            key_bytes = key_file.read_bytes().strip()
                            if key_bytes and len(key_bytes) >= 16:
                                return key_bytes
                    except OSError:
                        pass
                    time.sleep(0.01)
                raise ProposalStoreError(f"Server signing key in '{key_file}' timed out waiting for concurrent initialization.")
            except OSError as e:
                raise ProposalStoreError(f"Failed to write server signing key '{key_file}': {e}")

    @classmethod
    def _get_store_dir(cls, canonical_root: Path) -> Path:
        resolved_root = canonical_root.expanduser().resolve()
        gf_dir = resolved_root / ".ghostflow"
        gf_dir.mkdir(parents=True, exist_ok=True)

        gitignore_path = gf_dir / ".gitignore"
        if not gitignore_path.exists():
            try:
                gitignore_path.write_text("*\n", encoding="utf-8")
            except OSError:
                pass

        store_dir = (gf_dir / "proposals").resolve()
        try:
            store_dir.relative_to(resolved_root)
        except ValueError:
            raise ProposalStoreError(
                f"Storage directory '{store_dir}' escapes canonical project root '{resolved_root}'."
            )
        store_dir.mkdir(parents=True, exist_ok=True)
        return store_dir

    @classmethod
    def _compute_record_signature(cls, record_dict: dict[str, Any], secret_key: bytes | None = None) -> str:
        """Compute cryptographic HMAC-SHA256 of the record data excluding the signature itself."""
        if secret_key is None:
            secret_key = cls.get_signing_key()
        if not secret_key or len(secret_key) < 16:
            raise ProposalStoreError("Cryptographic signing key is missing or invalid.")
        data_copy = {k: v for k, v in record_dict.items() if k != "record_signature"}
        serialized = json.dumps(data_copy, sort_keys=True)
        return hmac.new(secret_key, serialized.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def save_proposal(
        cls,
        project_root: Path,
        proposal: IntelligentRepairProposal,
        ttl_seconds: int = DEFAULT_PROPOSAL_TTL_SECONDS,
        allowed_roots: list[Path] | None = None,
    ) -> ServerProposalRecord:
        """Persist a new validated proposal in server-side storage."""
        canonical_root = project_root.expanduser().resolve()
        store_dir = cls._get_store_dir(canonical_root)

        # File and excerpt hashes to bind
        file_hashes: dict[str, str] = {}
        excerpt_hashes: dict[str, str] = {}

        for f in proposal.affected_files:
            abs_path = validate_safe_path(f.rel_path, canonical_root, allowed_roots)
            if not abs_path.is_file():
                raise ProposalStoreError(f"Target file does not exist: '{f.rel_path}'.")
            curr_hash = hashlib.sha256(abs_path.read_bytes()).hexdigest()
            file_hashes[f.rel_path] = curr_hash
            for h in f.hunks:
                excerpt_hashes[h.hunk_id] = h.excerpt_sha256

        record = ServerProposalRecord(
            proposal_id=proposal.proposal_id,
            canonical_project_root=str(canonical_root),
            project_root_hash=hashlib.sha256(str(canonical_root).encode("utf-8")).hexdigest()[:16],
            created_at=proposal.created_at,
            expires_at=proposal.expires_at,
            proposal=proposal,
            file_hashes=file_hashes,
            excerpt_hashes=excerpt_hashes,
            state=proposal.approval_state.value if hasattr(proposal.approval_state, "value") else str(proposal.approval_state),
        )

        record_dict = {
            "proposal_id": record.proposal_id,
            "canonical_project_root": record.canonical_project_root,
            "project_root_hash": record.project_root_hash,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "proposal": asdict(record.proposal),
            "file_hashes": record.file_hashes,
            "excerpt_hashes": record.excerpt_hashes,
            "state": record.state,
            "applied_at": record.applied_at,
            "approved_at": record.approved_at,
            "approved_by": record.approved_by,
            "rejected_at": record.rejected_at,
            "rejection_reason": record.rejection_reason,
            "transaction_id": record.transaction_id,
            "verification_result": record.verification_result,
        }
        record_signature = cls._compute_record_signature(record_dict)
        record_dict["record_signature"] = record_signature
        record.record_signature = record_signature

        # Atomic file write
        target_path = store_dir / f"{proposal.proposal_id}.json"
        if target_path.parent.resolve() != store_dir:
            raise ProposalStoreError(f"Proposal path '{target_path}' escapes proposals directory.")

        tmp_path = store_dir / f".tmp_{proposal.proposal_id}.json"
        tmp_path.write_text(json.dumps(record_dict, indent=2), encoding="utf-8")
        with open(tmp_path, "r+b") as tf:
            tf.flush()
            os.fsync(tf.fileno())
        os.replace(tmp_path, target_path)

        return record

    @classmethod
    def get_proposal_record(
        cls,
        project_root: Path,
        proposal_id: str,
        validate_disk_hashes: bool = True,
        allowed_roots: list[Path] | None = None,
    ) -> ServerProposalRecord:
        """Retrieve and cryptographically validate a proposal record from server storage."""
        if not PROP_ID_RE.match(proposal_id):
            raise ValueError(f"Invalid proposal ID format: '{proposal_id}'.")

        canonical_root = project_root.expanduser().resolve()
        store_dir = cls._get_store_dir(canonical_root)
        proposal_path = store_dir / f"{proposal_id}.json"

        if not proposal_path.exists():
            raise ProposalNotFoundError(f"Proposal '{proposal_id}' was not found in project store.")

        try:
            data = json.loads(proposal_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as err:
            raise ProposalTamperedError(f"Malformed proposal record for '{proposal_id}': {err}")

        # 1. Signature and integrity verification
        stored_signature = data.get("record_signature")
        if not stored_signature:
            raise ProposalTamperedError(f"Proposal record '{proposal_id}' is missing cryptographic signature.")

        computed_signature = cls._compute_record_signature(data)
        if not hmac.compare_digest(stored_signature, computed_signature):
            raise ProposalTamperedError(f"Proposal record '{proposal_id}' signature mismatch (tampering detected).")

        # 2. Project root binding check
        record_root = Path(data.get("canonical_project_root", "")).expanduser().resolve()
        if record_root != canonical_root:
            raise ProposalProjectMismatchError(
                f"Proposal '{proposal_id}' belongs to project '{record_root}', not '{canonical_root}'."
            )

        # 3. Check expiration
        now_iso = datetime.now(timezone.utc).isoformat()
        expires_at = data.get("expires_at", "")
        if expires_at and now_iso > expires_at:
            if data.get("state") != ProposalApprovalState.EXPIRED.value:
                with ProposalLock(canonical_root, proposal_id):
                    data["state"] = ProposalApprovalState.EXPIRED.value
                    data["record_signature"] = cls._compute_record_signature(data)
                    tmp_exp = store_dir / f".tmp_exp_{proposal_id}.json"
                    tmp_exp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                    os.replace(tmp_exp, proposal_path)
            raise ProposalExpiredError(f"Proposal '{proposal_id}' expired at {expires_at}.")

        # 4. Check single-use state
        current_state = data.get("state")
        if current_state == ProposalApprovalState.APPLIED.value:
            raise ProposalAlreadyAppliedError(f"Proposal '{proposal_id}' has already been applied and cannot be reused.")

        # 5. Check on-disk file hash drift if requested
        if validate_disk_hashes:
            file_hashes: dict[str, str] = data.get("file_hashes", {})
            drifted_files: list[str] = []
            for rel_path, expected_hash in file_hashes.items():
                try:
                    abs_path = validate_safe_path(rel_path, canonical_root, allowed_roots)
                    if not abs_path.is_file():
                        drifted_files.append(f"{rel_path} (deleted/missing)")
                        continue
                    current_hash = hashlib.sha256(abs_path.read_bytes()).hexdigest()
                    if current_hash != expected_hash:
                        drifted_files.append(f"{rel_path} (content modified)")
                except Exception as e:
                    drifted_files.append(f"{rel_path} ({e})")

            if drifted_files:
                with ProposalLock(canonical_root, proposal_id):
                    data["state"] = ProposalApprovalState.STALE.value
                    data["record_signature"] = cls._compute_record_signature(data)
                    tmp_stale = store_dir / f".tmp_stale_{proposal_id}.json"
                    tmp_stale.write_text(json.dumps(data, indent=2), encoding="utf-8")
                    os.replace(tmp_stale, proposal_path)
                raise ProposalStaleError(
                    f"Proposal '{proposal_id}' is stale. File(s) drifted since generation: {', '.join(drifted_files)}."
                )

        # Deserialize proposal
        prop_data = data["proposal"]
        verification_plan = ProposalVerificationPlan(**prop_data.get("verification_plan", {}))
        affected_files: list[ProposalFile] = []

        for f_data in prop_data.get("affected_files", []):
            hunks = [PatchHunk(**h) for h in f_data.get("hunks", [])]
            f_kwargs = {k: v for k, v in f_data.items() if k != "hunks"}
            affected_files.append(ProposalFile(hunks=hunks, **f_kwargs))

        ai_meta = None
        if "ai_advisory" in prop_data and prop_data["ai_advisory"]:
            ai_data = prop_data["ai_advisory"]
            analysis_dict = ai_data.get("analysis", {})
            analysis_obj = TripartiteAnalysis(**analysis_dict)
            ai_meta = AIAdvisoryMetadata(
                analysis=analysis_obj,
                **{k: v for k, v in ai_data.items() if k != "analysis"},
            )

        prop_kwargs = {
            k: v for k, v in prop_data.items()
            if k not in ("verification_plan", "affected_files", "proposal_origin", "approval_state", "ai_advisory")
        }
        proposal_obj = IntelligentRepairProposal(
            verification_plan=verification_plan,
            affected_files=affected_files,
            proposal_origin=ProposalOrigin(prop_data.get("proposal_origin", "deterministic")),
            approval_state=ProposalApprovalState(data.get("state", "pending_review")),
            ai_advisory=ai_meta,
            **prop_kwargs,
        )

        record_kwargs = {
            k: v for k, v in data.items()
            if k not in ("proposal",)
        }
        return ServerProposalRecord(proposal=proposal_obj, **record_kwargs)

    @classmethod
    def approve_proposal(
        cls,
        project_root: Path,
        proposal_id: str,
        approved_by: str = "developer",
        allowed_roots: list[Path] | None = None,
    ) -> ServerProposalRecord:
        """Explicitly approve a pending proposal after developer review.

        Binds to exact proposal version and revalidates file hashes immediately before approving.
        Rejects expired, stale, modified, rejected or already-applied proposals.
        """
        if not PROP_ID_RE.match(proposal_id):
            raise ValueError(f"Invalid proposal ID format: '{proposal_id}'.")

        canonical_root = project_root.expanduser().resolve()
        store_dir = cls._get_store_dir(canonical_root)
        proposal_path = store_dir / f"{proposal_id}.json"

        if not proposal_path.exists():
            raise ProposalNotFoundError(f"Proposal '{proposal_id}' not found.")

        with ProposalLock(canonical_root, proposal_id):
            try:
                data = json.loads(proposal_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as err:
                raise ProposalTamperedError(f"Malformed proposal record for '{proposal_id}': {err}")

            # Verify cryptographic signature
            stored_signature = data.get("record_signature")
            if not stored_signature:
                raise ProposalTamperedError(f"Proposal record '{proposal_id}' is missing cryptographic signature.")
            computed_signature = cls._compute_record_signature(data)
            if not hmac.compare_digest(stored_signature, computed_signature):
                raise ProposalTamperedError(f"Proposal record '{proposal_id}' signature mismatch (tampering detected).")

            # Check project root binding
            record_root = Path(data.get("canonical_project_root", "")).expanduser().resolve()
            if record_root != canonical_root:
                raise ProposalProjectMismatchError(
                    f"Proposal '{proposal_id}' belongs to project '{record_root}', not '{canonical_root}'."
                )

            # Check expiration
            now_iso = datetime.now(timezone.utc).isoformat()
            expires_at = data.get("expires_at", "")
            if expires_at and now_iso > expires_at:
                data["state"] = ProposalApprovalState.EXPIRED.value
                data["record_signature"] = cls._compute_record_signature(data)
                tmp_exp = store_dir / f".tmp_exp_{proposal_id}.json"
                tmp_exp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                os.replace(tmp_exp, proposal_path)
                raise ProposalExpiredError(f"Proposal '{proposal_id}' expired at {expires_at}.")

            current_state = data.get("state")
            if current_state == ProposalApprovalState.APPLIED.value:
                raise ProposalAlreadyAppliedError(f"Proposal '{proposal_id}' has already been applied and cannot be approved.")
            if current_state == ProposalApprovalState.REJECTED.value:
                raise ProposalStoreError(f"Proposal '{proposal_id}' was rejected and cannot be approved.")
            if current_state == ProposalApprovalState.EXPIRED.value:
                raise ProposalExpiredError(f"Proposal '{proposal_id}' is expired.")
            if current_state == ProposalApprovalState.STALE.value:
                raise ProposalStaleError(f"Proposal '{proposal_id}' is stale.")

            # Validate disk hashes immediately before approval
            file_hashes: dict[str, str] = data.get("file_hashes", {})
            drifted_files: list[str] = []
            for rel_path, expected_hash in file_hashes.items():
                try:
                    abs_path = validate_safe_path(rel_path, canonical_root, allowed_roots)
                    if not abs_path.is_file():
                        drifted_files.append(f"{rel_path} (deleted/missing)")
                        continue
                    current_hash = hashlib.sha256(abs_path.read_bytes()).hexdigest()
                    if current_hash != expected_hash:
                        drifted_files.append(f"{rel_path} (content modified)")
                except Exception as e:
                    drifted_files.append(f"{rel_path} ({e})")

            if drifted_files:
                data["state"] = ProposalApprovalState.STALE.value
                data["record_signature"] = cls._compute_record_signature(data)
                tmp_stale = store_dir / f".tmp_stale_{proposal_id}.json"
                tmp_stale.write_text(json.dumps(data, indent=2), encoding="utf-8")
                os.replace(tmp_stale, proposal_path)
                raise ProposalStaleError(
                    f"Proposal '{proposal_id}' is stale. File(s) drifted before approval: {', '.join(drifted_files)}."
                )

            # Transition to APPROVED
            data["state"] = ProposalApprovalState.APPROVED.value
            data["approved_at"] = now_iso
            data["approved_by"] = approved_by
            if "proposal" in data:
                data["proposal"]["approval_state"] = ProposalApprovalState.APPROVED.value
            data["record_signature"] = cls._compute_record_signature(data)

            tmp_path = store_dir / f".tmp_appr_{proposal_id}.json"
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            with open(tmp_path, "r+b") as tf:
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, proposal_path)

        return cls.get_proposal_record(canonical_root, proposal_id, validate_disk_hashes=False, allowed_roots=allowed_roots)

    @classmethod
    def reject_proposal(
        cls,
        project_root: Path,
        proposal_id: str,
        reason: str = "",
        allowed_roots: list[Path] | None = None,
    ) -> ServerProposalRecord:
        """Explicitly reject a proposal."""
        if not PROP_ID_RE.match(proposal_id):
            raise ValueError(f"Invalid proposal ID format: '{proposal_id}'.")

        canonical_root = project_root.expanduser().resolve()
        store_dir = cls._get_store_dir(canonical_root)
        proposal_path = store_dir / f"{proposal_id}.json"

        if not proposal_path.exists():
            raise ProposalNotFoundError(f"Proposal '{proposal_id}' not found.")

        with ProposalLock(canonical_root, proposal_id):
            try:
                data = json.loads(proposal_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as err:
                raise ProposalTamperedError(f"Malformed proposal record for '{proposal_id}': {err}")

            stored_signature = data.get("record_signature")
            if not stored_signature:
                raise ProposalTamperedError(f"Proposal record '{proposal_id}' is missing cryptographic signature.")
            computed_signature = cls._compute_record_signature(data)
            if not hmac.compare_digest(stored_signature, computed_signature):
                raise ProposalTamperedError(f"Proposal record '{proposal_id}' signature mismatch (tampering detected).")

            if data.get("state") == ProposalApprovalState.APPLIED.value:
                raise ProposalAlreadyAppliedError(f"Proposal '{proposal_id}' has already been applied and cannot be rejected.")

            data["state"] = ProposalApprovalState.REJECTED.value
            data["rejected_at"] = datetime.now(timezone.utc).isoformat()
            data["rejection_reason"] = reason
            if "proposal" in data:
                data["proposal"]["approval_state"] = ProposalApprovalState.REJECTED.value
            data["record_signature"] = cls._compute_record_signature(data)

            tmp_path = store_dir / f".tmp_rej_{proposal_id}.json"
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            with open(tmp_path, "r+b") as tf:
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, proposal_path)

        return cls.get_proposal_record(canonical_root, proposal_id, validate_disk_hashes=False, allowed_roots=allowed_roots)

    @classmethod
    def mark_applied(
        cls,
        project_root: Path,
        proposal_id: str,
        transaction_id: str | None = None,
        verification_result: dict[str, Any] | None = None,
    ) -> None:
        """Mark a proposal as APPLIED in storage so it cannot be executed again."""
        if not PROP_ID_RE.match(proposal_id):
            raise ValueError(f"Invalid proposal ID format: '{proposal_id}'.")

        canonical_root = project_root.expanduser().resolve()
        store_dir = cls._get_store_dir(canonical_root)
        proposal_path = store_dir / f"{proposal_id}.json"

        if not proposal_path.exists():
            raise ProposalNotFoundError(f"Proposal '{proposal_id}' not found.")

        with ProposalLock(canonical_root, proposal_id):
            try:
                data = json.loads(proposal_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as err:
                raise ProposalTamperedError(f"Malformed proposal record for '{proposal_id}': {err}")

            if data.get("state") == ProposalApprovalState.APPLIED.value:
                raise ProposalAlreadyAppliedError(
                    f"Proposal '{proposal_id}' has already been applied and cannot be reused."
                )

            data["state"] = ProposalApprovalState.APPLIED.value
            data["applied_at"] = datetime.now(timezone.utc).isoformat()
            if transaction_id:
                data["transaction_id"] = transaction_id
            if verification_result:
                data["verification_result"] = verification_result
            if "proposal" in data:
                data["proposal"]["approval_state"] = ProposalApprovalState.APPLIED.value
            data["record_signature"] = cls._compute_record_signature(data)

            tmp_path = store_dir / f".tmp_{proposal_id}.json"
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            with open(tmp_path, "r+b") as tf:
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, proposal_path)
