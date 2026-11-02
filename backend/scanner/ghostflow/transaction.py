from __future__ import annotations

import enum
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .repair import validate_safe_path

TX_ID_RE = re.compile(r"^tx_\d{8}_\d{6}_[a-f0-9]{8}$")
LOCK_TIMEOUT_SECONDS = 300  # 5 minutes


class TransactionState(str, enum.Enum):
    PENDING = "pending"
    PRE_FLIGHT_PASSED = "pre_flight_passed"
    BACKUP_STAGED = "backup_staged"
    APPLYING = "applying"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class TransactionError(Exception):
    """Base exception for repair transaction failures."""
    pass


class PreFlightValidationError(TransactionError):
    """Raised when pre-flight checks fail before any files are modified."""
    pass


class ConcurrentModificationError(TransactionError):
    """Raised when a target file was modified concurrently by another process."""
    pass


class BackupCorruptedError(TransactionError):
    """Raised when a backup snapshot fails its cryptographic integrity check."""
    pass


class RestorationCorruptionError(TransactionError):
    """Raised when a restored file does not match exact pre-repair bytes."""
    pass


class ConcurrentModificationConflictError(TransactionError):
    """Raised when a file was modified externally after replacement, preventing safe automated rollback."""
    pass


class ProjectLockError(TransactionError):
    """Raised when the project is locked by another transaction."""
    pass


@dataclass
class FileRepairTarget:
    """Represents a single file modification target within a multi-file transaction."""
    rel_path: str
    expected_file_hash: str  # SHA-256 hex digest of file bytes before modification
    replacement_bytes: bytes  # Exact byte payload to write
    expected_excerpt_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class JournalEntry:
    """Record of a target file's state within the transaction journal."""
    target_rel_path: str
    abs_path: str
    snapshot_rel_path: str
    expected_sha256: str
    replacement_sha256: str
    original_mode: int
    status: str  # 'staged', 'replacing', 'replaced', 'restoring', 'restored', 'failed'
    error: str | None = None


@dataclass
class TransactionManifest:
    """Serializable record of the complete transaction state and journal."""
    transaction_id: str
    canonical_project_root: str
    created_at: str
    state: str
    proposal_id: str | None
    entries: list[JournalEntry] = field(default_factory=list)
    completed_at: str | None = None
    error_message: str | None = None


@dataclass
class TransactionResult:
    """Result returned after applying or rolling back a transaction."""
    transaction_id: str
    success: bool
    state: TransactionState
    modified_files: list[str] = field(default_factory=list)
    restored_files: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    error_message: str | None = None
    manifest_path: str | None = None


@dataclass
class CrashRecoveryReport:
    """Report of recovery actions performed for an interrupted transaction."""
    transaction_id: str
    recovered: bool
    prior_state: str
    restored_files: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    cleaned_temp_files: list[str] = field(default_factory=list)
    error_message: str | None = None


def is_pid_alive(pid: int) -> bool:
    """Check if process ID is alive across Windows and POSIX."""
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (OSError, Exception):
        return False


class ProjectRepairLock:
    """Per-project lock preventing concurrent repair transactions."""

    def __init__(self, project_root: Path, transaction_id: str, timeout: float = 0.0):
        self.project_root = project_root.expanduser().resolve()
        self.transaction_id = transaction_id
        self.timeout = timeout
        self.lock_dir = self.project_root / ".ghostflow" / "locks"
        self.lock_file = self.lock_dir / "repair.lock"
        self.acquired = False

    def acquire(self) -> None:
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        start_time = time.time()
        while True:
            if self.lock_file.exists():
                try:
                    data = json.loads(self.lock_file.read_text(encoding="utf-8"))
                    holder_pid = data.get("pid", 0)
                    holder_tx = data.get("transaction_id", "")
                    acquired_at = data.get("acquired_at", 0)

                    # Re-entrancy check: same transaction and same process
                    if holder_pid == os.getpid() and holder_tx == self.transaction_id:
                        self.acquired = True
                        return

                    # Check if holder is still running
                    now = time.time()
                    if is_pid_alive(holder_pid) and (now - acquired_at < LOCK_TIMEOUT_SECONDS):
                        if time.time() - start_time < self.timeout:
                            time.sleep(0.05)
                            continue
                        raise ProjectLockError(
                            f"Project '{self.project_root}' is locked by active transaction "
                            f"'{holder_tx}' (PID {holder_pid})."
                        )
                except (json.JSONDecodeError, OSError):
                    # Malformed or corrupt lock file; safe to reclaim
                    pass

            # Write lock file
            lock_data = {
                "lock_id": uuid.uuid4().hex,
                "transaction_id": self.transaction_id,
                "pid": os.getpid(),
                "acquired_at": time.time(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            # Atomic lock write
            temp_lock = self.lock_dir / f".tmp_{self.transaction_id}.lock"
            temp_lock.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
            os.replace(temp_lock, self.lock_file)
            self.acquired = True
            return

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            if self.lock_file.exists():
                try:
                    data = json.loads(self.lock_file.read_text(encoding="utf-8"))
                    if data.get("transaction_id") == self.transaction_id:
                        self.lock_file.unlink(missing_ok=True)
                except Exception:
                    self.lock_file.unlink(missing_ok=True)
        finally:
            self.acquired = False

    def __enter__(self) -> ProjectRepairLock:
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class RepairTransactionManager:
    """Manages multi-file repair transactions with strict atomicity and compensation."""

    @staticmethod
    def generate_transaction_id() -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rand = uuid.uuid4().hex[:8]
        return f"tx_{timestamp}_{rand}"

    @classmethod
    def _atomic_replace(cls, src: Path, dst: Path) -> None:
        """Atomically replace dst with src on the same filesystem."""
        os.replace(src, dst)

    @classmethod
    def _save_journal_file(cls, tmp: Path, dst: Path) -> None:
        """Atomically write journal file."""
        os.replace(tmp, dst)

    @classmethod
    def _get_tx_dir(cls, project_root: Path, transaction_id: str) -> Path:
        d = project_root / ".ghostflow" / "backups" / transaction_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    @classmethod
    def get_manifest(
        cls,
        project_root: Path,
        transaction_id: str,
        allowed_roots: list[Path] | None = None,
    ) -> TransactionManifest | None:
        """Retrieve the TransactionManifest for a given transaction ID if it exists."""
        canonical_root = project_root.expanduser().resolve()
        if not TX_ID_RE.match(transaction_id):
            return None
        tx_dir = canonical_root / ".ghostflow" / "backups" / transaction_id
        journal_file = tx_dir / "journal.json"
        if not journal_file.exists():
            return None
        try:
            data = json.loads(journal_file.read_text(encoding="utf-8"))
            entries = [JournalEntry(**e) for e in data.get("entries", [])]
            return TransactionManifest(
                transaction_id=data.get("transaction_id", transaction_id),
                canonical_project_root=data.get("canonical_project_root", str(canonical_root)),
                created_at=data.get("created_at", ""),
                state=data.get("state", ""),
                proposal_id=data.get("proposal_id"),
                entries=entries,
                completed_at=data.get("completed_at"),
                error_message=data.get("error_message"),
            )
        except Exception:
            return None

    @classmethod
    def execute_transaction(
        cls,
        project_root: Path,
        targets: list[FileRepairTarget],
        proposal_id: str | None = None,
        allowed_roots: list[Path] | None = None,
    ) -> TransactionResult:
        """Execute a multi-file repair transaction with complete safety guarantees."""
        canonical_root = project_root.expanduser().resolve()
        tx_id = cls.generate_transaction_id()
        tx_dir = cls._get_tx_dir(canonical_root, tx_id)
        snapshots_dir = tx_dir / "snapshots"
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        journal_file = tx_dir / "journal.json"

        manifest = TransactionManifest(
            transaction_id=tx_id,
            canonical_project_root=str(canonical_root),
            created_at=datetime.now(timezone.utc).isoformat(),
            state=TransactionState.PENDING.value,
            proposal_id=proposal_id,
        )

        def _save_journal() -> None:
            tmp = tx_dir / ".journal.tmp"
            tmp.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
            with open(tmp, "r+b") as f:
                f.flush()
                os.fsync(f.fileno())
            cls._save_journal_file(tmp, journal_file)

        # 2. Acquire the project-level transaction lock
        lock = ProjectRepairLock(canonical_root, tx_id)
        lock.acquire()

        staged_temp_files: list[tuple[Path, Path, JournalEntry]] = []

        try:
            # 3 & 4. Recover only interrupted transactions while holding the project lock
            # 5. Never remove staged or restoration files belonging to an active transaction (ignore_tx_id=tx_id)
            prior_recoveries = cls.recover_interrupted_transactions(
                canonical_root,
                allowed_roots=allowed_roots,
                ignore_tx_id=tx_id,
                holding_project_lock=True,
            )
            # 6. Abort the new transaction if recovery reports unresolved conflicts
            for rec in prior_recoveries:
                if rec.conflicts or not rec.recovered:
                    raise TransactionError(
                        f"Cannot start transaction '{tx_id}': prior transaction '{rec.transaction_id}' "
                        f"has unresolved conflicts ({', '.join(rec.conflicts)}). Manual resolution required."
                    )

            # 7. Continue with the new transaction only after recovery succeeds

            # ---------------------------------------------------------
            # PHASE 1: Pre-Flight Validation (Read-Only)
            # ---------------------------------------------------------
            if not targets:
                raise PreFlightValidationError("Transaction contains no file repair targets.")

            validated_targets: list[tuple[Path, FileRepairTarget, bytes, int]] = []
            seen_paths: set[Path] = set()

            for target in targets:
                # 1. Path safety and containment
                abs_path = validate_safe_path(target.rel_path, canonical_root, allowed_roots)
                if abs_path in seen_paths:
                    raise PreFlightValidationError(f"Duplicate target path in transaction: '{target.rel_path}'.")
                seen_paths.add(abs_path)

                if not abs_path.is_file():
                    raise PreFlightValidationError(
                        f"Target path does not exist or is not a regular file: '{target.rel_path}'."
                    )

                # 2. Check current content and hash
                original_bytes = abs_path.read_bytes()
                curr_hash = hashlib.sha256(original_bytes).hexdigest()
                if curr_hash != target.expected_file_hash:
                    raise PreFlightValidationError(
                        f"File hash drift on '{target.rel_path}': expected {target.expected_file_hash[:8]}..., "
                        f"found {curr_hash[:8]}... Project has been modified."
                    )

                # 3. File permissions
                mode = os.stat(abs_path).st_mode
                validated_targets.append((abs_path, target, original_bytes, mode))

            manifest.state = TransactionState.PRE_FLIGHT_PASSED.value
            _save_journal()

            # ---------------------------------------------------------
            # PHASE 2: Multi-File Backup Staging
            # ---------------------------------------------------------
            for abs_path, target, original_bytes, mode in validated_targets:
                rel_hash = hashlib.sha256(target.rel_path.encode("utf-8")).hexdigest()[:16]
                snapshot_name = f"snap_{rel_hash}.bin"
                snapshot_path = snapshots_dir / snapshot_name

                # Write snapshot bytes
                snapshot_path.write_bytes(original_bytes)
                with open(snapshot_path, "r+b") as sf:
                    sf.flush()
                    os.fsync(sf.fileno())

                # Verify snapshot integrity immediately
                snap_bytes = snapshot_path.read_bytes()
                snap_hash = hashlib.sha256(snap_bytes).hexdigest()
                if snap_hash != target.expected_file_hash or snap_bytes != original_bytes:
                    raise BackupCorruptedError(f"Snapshot verification failed for '{target.rel_path}'.")

                entry = JournalEntry(
                    target_rel_path=target.rel_path,
                    abs_path=str(abs_path),
                    snapshot_rel_path=f"snapshots/{snapshot_name}",
                    expected_sha256=target.expected_file_hash,
                    replacement_sha256=hashlib.sha256(target.replacement_bytes).hexdigest(),
                    original_mode=mode,
                    status="staged",
                )
                manifest.entries.append(entry)

            manifest.state = TransactionState.BACKUP_STAGED.value
            _save_journal()

            # ---------------------------------------------------------
            # PHASE 3: Prepare Staged Files on Same Filesystem
            # ---------------------------------------------------------
            for (abs_path, target, _, mode), entry in zip(validated_targets, manifest.entries):
                # Staged temporary replacement file in the target's parent directory
                parent_dir = abs_path.parent
                tmp_replacement = parent_dir / f".gf_staged_{tx_id}_{abs_path.name}.tmp"

                tmp_replacement.write_bytes(target.replacement_bytes)
                try:
                    os.chmod(tmp_replacement, mode)
                except OSError:
                    pass

                with open(tmp_replacement, "r+b") as tf:
                    tf.flush()
                    os.fsync(tf.fileno())

                # Validate staged content before replacement
                staged_bytes = tmp_replacement.read_bytes()
                if hashlib.sha256(staged_bytes).hexdigest() != entry.replacement_sha256:
                    raise TransactionError(f"Staged replacement corruption for '{target.rel_path}'.")

                staged_temp_files.append((tmp_replacement, abs_path, entry))

            # ---------------------------------------------------------
            # PHASE 4: Atomic Replacements with Pre-Replacement Check
            # ---------------------------------------------------------
            manifest.state = TransactionState.APPLYING.value
            _save_journal()

            for tmp_replacement, abs_path, entry in staged_temp_files:
                # Concurrent modification check immediately before os.replace
                curr_bytes = abs_path.read_bytes()
                curr_sha = hashlib.sha256(curr_bytes).hexdigest()
                if curr_sha != entry.expected_sha256:
                    raise ConcurrentModificationError(
                        f"Concurrent modification detected on '{entry.target_rel_path}' immediately "
                        f"before replacement (expected {entry.expected_sha256[:8]}, found {curr_sha[:8]})."
                    )

                # Record intention in journal before replacement
                entry.status = "replacing"
                _save_journal()

                # Perform atomic replacement
                cls._atomic_replace(tmp_replacement, abs_path)

                # Record success in journal
                entry.status = "replaced"
                _save_journal()

            # All replacements completed successfully
            manifest.state = TransactionState.COMMITTED.value
            manifest.completed_at = datetime.now(timezone.utc).isoformat()
            _save_journal()

            return TransactionResult(
                transaction_id=tx_id,
                success=True,
                state=TransactionState.COMMITTED,
                modified_files=[e.target_rel_path for e in manifest.entries],
                manifest_path=str(journal_file),
            )

        except Exception as exc:
            # ---------------------------------------------------------
            # EMERGENCY RECOVERY / ROLLBACK
            # ---------------------------------------------------------
            manifest.state = TransactionState.ROLLING_BACK.value
            manifest.error_message = str(exc)
            _save_journal()

            restored_files: list[str] = []
            conflict_files: list[str] = []
            restoration_failed = False

            # Clean up un-applied staged temporary files
            for tmp_replacement, _, _ in staged_temp_files:
                if tmp_replacement.exists():
                    try:
                        tmp_replacement.unlink(missing_ok=True)
                    except OSError:
                        pass

            # Restore any files marked 'replaced' or 'replacing'
            for entry in reversed(manifest.entries):
                if entry.status in ("replaced", "replacing", "restoring"):
                    try:
                        cls._restore_single_entry(canonical_root, tx_dir, entry, tx_id)
                        restored_files.append(entry.target_rel_path)
                    except ConcurrentModificationConflictError as conf_err:
                        conflict_files.append(entry.target_rel_path)
                        entry.status = "conflict"
                        entry.error = str(conf_err)
                    except Exception as rest_err:
                        restoration_failed = True
                        entry.status = "failed"
                        entry.error = str(rest_err)

            manifest.state = (
                TransactionState.FAILED.value
                if restoration_failed
                else TransactionState.ROLLED_BACK.value
            )
            manifest.completed_at = datetime.now(timezone.utc).isoformat()
            _save_journal()

            if restoration_failed:
                raise RestorationCorruptionError(
                    f"CRITICAL: Failed to cleanly restore all files in transaction '{tx_id}'. "
                    f"Initial error: {exc}"
                )

            return TransactionResult(
                transaction_id=tx_id,
                success=False,
                state=TransactionState.ROLLED_BACK,
                restored_files=restored_files,
                conflicts=conflict_files,
                error_message=str(exc),
                manifest_path=str(journal_file),
            )

        finally:
            lock.release()

    @classmethod
    def _restore_single_entry(
        cls,
        canonical_root: Path,
        tx_dir: Path,
        entry: JournalEntry,
        tx_id: str,
    ) -> None:
        """Restore a single journal entry from its snapshot with byte-for-byte verification.

        Guarantees that files modified externally after replacement are NEVER blindly overwritten.
        """
        target_path = Path(entry.abs_path)
        snapshot_path = tx_dir / entry.snapshot_rel_path

        if not snapshot_path.exists():
            raise BackupCorruptedError(f"Snapshot missing: '{snapshot_path}'.")

        snapshot_bytes = snapshot_path.read_bytes()
        snapshot_hash = hashlib.sha256(snapshot_bytes).hexdigest()
        if snapshot_hash != entry.expected_sha256:
            raise BackupCorruptedError(
                f"Snapshot hash corrupted for '{entry.target_rel_path}': "
                f"expected {entry.expected_sha256}, found {snapshot_hash}."
            )

        if target_path.exists():
            current_bytes = target_path.read_bytes()
            current_hash = hashlib.sha256(current_bytes).hexdigest()

            # Already restored to exact pre-repair state
            if current_hash == entry.expected_sha256 or current_bytes == snapshot_bytes:
                entry.status = "restored"
                return

            # Check if developer/external process modified the file after replacement
            if entry.status in ("replaced", "replacing") and current_hash != entry.replacement_sha256:
                raise ConcurrentModificationConflictError(
                    f"Conflict detected on '{entry.target_rel_path}': content was modified externally "
                    f"after replacement (hash {current_hash[:8]}... != expected replacement {entry.replacement_sha256[:8]}...). "
                    "Restoration aborted to preserve external developer changes. Manual intervention required."
                )

        entry.status = "restoring"

        # Stage restoration file on same filesystem
        tmp_restore = target_path.parent / f".gf_restore_{tx_id}_{target_path.name}.tmp"
        tmp_restore.write_bytes(snapshot_bytes)
        try:
            os.chmod(tmp_restore, entry.original_mode)
        except OSError:
            pass

        with open(tmp_restore, "r+b") as rf:
            rf.flush()
            os.fsync(rf.fileno())

        cls._atomic_replace(tmp_restore, target_path)

        # Verify exact byte equality
        current_bytes = target_path.read_bytes()
        if current_bytes != snapshot_bytes:
            raise RestorationCorruptionError(
                f"Restoration byte mismatch for '{entry.target_rel_path}'."
            )

        entry.status = "restored"

    @classmethod
    def rollback_transaction(
        cls,
        project_root: Path,
        transaction_id: str,
        allowed_roots: list[Path] | None = None,
    ) -> TransactionResult:
        """Manually trigger rollback for a previously committed transaction."""
        if not TX_ID_RE.match(transaction_id):
            raise ValueError(f"Invalid transaction ID format: '{transaction_id}'.")

        canonical_root = project_root.expanduser().resolve()
        tx_dir = cls._get_tx_dir(canonical_root, transaction_id)
        journal_file = tx_dir / "journal.json"

        if not journal_file.exists():
            raise ValueError(f"Transaction journal not found for '{transaction_id}'.")

        data = json.loads(journal_file.read_text(encoding="utf-8"))
        entries = [JournalEntry(**e) for e in data.get("entries", [])]

        lock = ProjectRepairLock(canonical_root, transaction_id)
        with lock:
            restored_files: list[str] = []
            conflict_files: list[str] = []
            for entry in reversed(entries):
                # Validate path containment
                validate_safe_path(entry.target_rel_path, canonical_root, allowed_roots)
                try:
                    cls._restore_single_entry(canonical_root, tx_dir, entry, transaction_id)
                    restored_files.append(entry.target_rel_path)
                except ConcurrentModificationConflictError as conf_err:
                    conflict_files.append(entry.target_rel_path)
                    entry.status = "conflict"
                    entry.error = str(conf_err)

            data["state"] = (
                TransactionState.FAILED.value
                if conflict_files
                else TransactionState.ROLLED_BACK.value
            )
            data["entries"] = [asdict(e) for e in entries]
            journal_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            return TransactionResult(
                transaction_id=transaction_id,
                success=len(conflict_files) == 0,
                state=TransactionState.FAILED if conflict_files else TransactionState.ROLLED_BACK,
                restored_files=restored_files,
                conflicts=conflict_files,
                error_message=f"Conflicts detected on {len(conflict_files)} file(s)" if conflict_files else None,
                manifest_path=str(journal_file),
            )

    @classmethod
    def recover_interrupted_transactions(
        cls,
        project_root: Path,
        allowed_roots: list[Path] | None = None,
        ignore_tx_id: str | None = None,
        holding_project_lock: bool = False,
    ) -> list[CrashRecoveryReport]:
        """Automatically detect and safely recover any crashed or interrupted transactions.

        Scans .ghostflow/backups for transactions left in non-terminal states.
        Never blindly restores files with external modifications; reports them as conflicts.
        """
        canonical_root = project_root.expanduser().resolve()
        backups_root = canonical_root / ".ghostflow" / "backups"
        if not backups_root.exists():
            return []

        reports: list[CrashRecoveryReport] = []
        terminal_states = {
            TransactionState.COMMITTED.value,
            TransactionState.ROLLED_BACK.value,
        }

        # Iterate over transaction directories
        for tx_dir in sorted(backups_root.iterdir()):
            if not tx_dir.is_dir() or not TX_ID_RE.match(tx_dir.name):
                continue
            if ignore_tx_id and tx_dir.name == ignore_tx_id:
                continue

            journal_file = tx_dir / "journal.json"
            if not journal_file.exists():
                continue

            try:
                data = json.loads(journal_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            current_state = data.get("state")
            if current_state in terminal_states:
                continue

            tx_id = data.get("transaction_id", tx_dir.name)
            entries = [JournalEntry(**e) for e in data.get("entries", [])]

            report = CrashRecoveryReport(
                transaction_id=tx_id,
                recovered=False,
                prior_state=current_state or "unknown",
            )

            lock = None
            if not holding_project_lock:
                lock = ProjectRepairLock(canonical_root, tx_id)
                try:
                    lock.acquire()
                except ProjectLockError:
                    # Still locked by an active process
                    continue

            try:
                # Clean up any leftover staged or restore temp files in project belonging ONLY to tx_id
                for entry in entries:
                    try:
                        p = validate_safe_path(entry.target_rel_path, canonical_root, allowed_roots)
                        parent = p.parent
                        staged_tmp = parent / f".gf_staged_{tx_id}_{p.name}.tmp"
                        restore_tmp = parent / f".gf_restore_{tx_id}_{p.name}.tmp"
                        for tmp_p in (staged_tmp, restore_tmp):
                            if tmp_p.exists():
                                tmp_p.unlink(missing_ok=True)
                                report.cleaned_temp_files.append(str(tmp_p))
                    except Exception:
                        pass

                # If no files reached 'replaced' or 'replacing', simple rollback of metadata
                active_entries = [
                    e for e in entries
                    if e.status in ("replaced", "replacing", "restoring")
                ]

                if not active_entries:
                    data["state"] = TransactionState.ROLLED_BACK.value
                    data["completed_at"] = datetime.now(timezone.utc).isoformat()
                    journal_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                    report.recovered = True
                    reports.append(report)
                    continue

                # Roll back replaced files safely with conflict detection
                for entry in reversed(active_entries):
                    try:
                        validate_safe_path(entry.target_rel_path, canonical_root, allowed_roots)
                        cls._restore_single_entry(canonical_root, tx_dir, entry, tx_id)
                        report.restored_files.append(entry.target_rel_path)
                    except ConcurrentModificationConflictError as conf_err:
                        report.conflicts.append(entry.target_rel_path)
                        entry.status = "conflict"
                        entry.error = str(conf_err)
                    except Exception as err:
                        report.conflicts.append(entry.target_rel_path)
                        entry.status = "failed"
                        entry.error = str(err)

                if report.conflicts:
                    data["state"] = TransactionState.FAILED.value
                    data["error_message"] = f"Recovery conflict on {len(report.conflicts)} file(s)"
                    report.recovered = False
                else:
                    data["state"] = TransactionState.ROLLED_BACK.value
                    report.recovered = True

                data["entries"] = [asdict(e) for e in entries]
                data["completed_at"] = datetime.now(timezone.utc).isoformat()
                journal_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                reports.append(report)

            finally:
                if lock is not None:
                    lock.release()

        return reports
