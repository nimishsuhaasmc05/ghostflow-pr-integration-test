"""Secure Remote GitHub Repository Scanner for GhostFlow.

Provides isolated shallow cloning, real-time resource limits during acquisition,
symlink escape neutralization, and static AST contract analysis for public GitHub repositories.
Code from scanned repositories is NEVER executed.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from .analyzer import scan_project

# Strict GitHub URL specification: https://github.com/{owner}/{repo}
# Owner: 1 to 39 alphanumeric chars or hyphens (not leading/trailing, no consecutive hyphens per spec)
# Repo: 1 to 100 alphanumeric chars, hyphens, underscores, or periods
GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})/([A-Za-z0-9_.-]{1,100})(?:\.git)?/?$"
)

# Default Safety & Resource Limits
DEFAULT_MAX_REPO_SIZE_BYTES: int = 500 * 1024 * 1024  # 500 MB default (configurable)
DEFAULT_MAX_SINGLE_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB per individual file (configurable)
DEFAULT_MAX_FILE_COUNT: int = 15_000  # 15,000 files default (configurable)
DEFAULT_MAX_CONCURRENT_SCANS: int = 2  # 2 simultaneous remote scans default (configurable)
DEFAULT_TIMEOUT_SECONDS: int = 45
MAX_TIMEOUT_SECONDS: int = 120

# Active limits (defaults can be overridden via server config env vars or directly in tests)
MAX_REPO_SIZE_BYTES: int = DEFAULT_MAX_REPO_SIZE_BYTES
MAX_SINGLE_FILE_BYTES: int = DEFAULT_MAX_SINGLE_FILE_BYTES
MAX_FILE_COUNT: int = DEFAULT_MAX_FILE_COUNT
MAX_CONCURRENT_REMOTE_SCANS: int = DEFAULT_MAX_CONCURRENT_SCANS


class ConcurrencyLimitError(RuntimeError):
    """Raised when maximum simultaneous remote scans are in progress."""
    pass


class RemoteScanConcurrencyManager:
    """Thread-safe manager for tracking and restricting concurrent remote scans."""

    def __init__(self) -> None:
        self._active_count = 0
        self._lock = threading.Lock()

    @property
    def max_concurrent(self) -> int:
        return get_max_concurrent_scans()

    @property
    def active_count(self) -> int:
        with self._lock:
            return self._active_count

    def acquire(self) -> bool:
        """Attempt to acquire a concurrency slot. Returns True if successful, False if at capacity."""
        with self._lock:
            if self._active_count >= self.max_concurrent:
                return False
            self._active_count += 1
            return True

    def release(self) -> None:
        """Release a previously acquired concurrency slot."""
        with self._lock:
            if self._active_count > 0:
                self._active_count -= 1

    def reset(self) -> None:
        """Reset slot counter (used for test isolation)."""
        with self._lock:
            self._active_count = 0


concurrency_manager = RemoteScanConcurrencyManager()


@contextmanager
def remote_scan_slot() -> Generator[None, None, None]:
    """Context manager acquiring and releasing a remote scan slot with guaranteed cleanup."""
    if not concurrency_manager.acquire():
        limit = concurrency_manager.max_concurrent
        raise ConcurrencyLimitError(
            f"Server busy: maximum concurrent remote scans ({limit}) reached. Please try again shortly."
        )
    try:
        yield
    finally:
        concurrency_manager.release()


def get_max_repo_size_bytes() -> int:
    """Read max repository size in bytes from server config or module default (500 MB)."""
    raw = os.environ.get("GHOSTFLOW_MAX_REPO_SIZE_MB")
    if raw is not None:
        try:
            val = int(raw.strip())
            # Enforce safe bounds: 1 MB to 2048 MB (2 GB)
            if 1 <= val <= 2048:
                return val * 1024 * 1024
        except ValueError:
            pass
    return MAX_REPO_SIZE_BYTES


def get_max_single_file_bytes() -> int:
    """Read max single file size in bytes from server config or module default (10 MB)."""
    raw = os.environ.get("GHOSTFLOW_MAX_SINGLE_FILE_MB")
    if raw is not None:
        try:
            val = int(raw.strip())
            # Safe bounds: 1 MB to 100 MB
            if 1 <= val <= 100:
                return val * 1024 * 1024
        except ValueError:
            pass
    return MAX_SINGLE_FILE_BYTES


def get_max_file_count() -> int:
    """Read max total file count from server config or module default (15,000)."""
    raw = os.environ.get("GHOSTFLOW_MAX_FILE_COUNT")
    if raw is not None:
        try:
            val = int(raw.strip())
            # Safe bounds: 100 to 100,000 files
            if 100 <= val <= 100_000:
                return val
        except ValueError:
            pass
    return MAX_FILE_COUNT


def get_max_concurrent_scans() -> int:
    """Read max simultaneous remote scans from server config or module default (2)."""
    raw = os.environ.get("GHOSTFLOW_MAX_CONCURRENT_REMOTE_SCANS")
    if raw is not None:
        try:
            val = int(raw.strip())
            # Safe bounds: 1 to 16
            if 1 <= val <= 16:
                return val
        except ValueError:
            pass
    return MAX_CONCURRENT_REMOTE_SCANS


def get_remote_resource_limits() -> dict[str, Any]:
    """Return current server-enforced resource and concurrency limits with enforcement classification."""
    return {
        "max_repo_size_bytes": get_max_repo_size_bytes(),
        "max_repo_size_mb": get_max_repo_size_bytes() // (1024 * 1024),
        "max_single_file_bytes": get_max_single_file_bytes(),
        "max_single_file_mb": get_max_single_file_bytes() // (1024 * 1024),
        "max_file_count": get_max_file_count(),
        "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
        "max_concurrent_scans": get_max_concurrent_scans(),
        "enforcement": {
            "hard_enforced": [
                "Real-time disk monitoring during Git shallow clone (kills process if exceeded)",
                "Pre-analysis repository size and single-file size verification",
                "Total file-count quota verification",
                "Subprocess execution timeout with SIGTERM/SIGKILL termination",
                "Symlink neutralization escaping repository boundary",
                "Thread-safe remote scan concurrency limit with immediate 429 rejection",
                "Strict read-only guard blocking repair proposals, patches, and rollbacks",
            ],
            "best_effort": [
                "Network streaming bandwidth throttling (delegated to Git HTTP transport)",
                "OS-level sandbox/cgroup process isolation (in-process / non-container environment)",
            ],
        },
    }


def validate_github_url(url: str) -> tuple[str, str, str]:
    """Validate a public GitHub HTTPS repository URL.

    Returns:
        tuple of (owner, repo_name, normalized_url)

    Raises:
        ValueError if the URL is invalid or attempts injection/traversal.
    """
    clean_url = url.strip()
    if clean_url.endswith("/"):
        clean_url = clean_url[:-1]
    if clean_url.endswith(".git"):
        clean_url = clean_url[:-4]

    match = GITHUB_URL_PATTERN.match(clean_url)
    if not match:
        raise ValueError(
            "Invalid GitHub repository URL. Format must be: https://github.com/owner/repository"
        )

    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]

    # Disallow path traversal, dots only, or suspicious names
    if repo in (".", "..") or "/" in repo or "\\" in repo:
        raise ValueError("Invalid repository name.")

    normalized_url = f"https://github.com/{owner}/{repo}"
    return owner, repo, normalized_url


def _sanitize_error(msg: str, temp_dir: Path | None = None) -> str:
    """Scrub local temporary paths and credentials from error messages."""
    if not msg:
        return ""
    clean = msg
    if temp_dir:
        clean = clean.replace(str(temp_dir), "<workspace>")
        clean = clean.replace(str(temp_dir).replace("\\", "/"), "<workspace>")
    temp_root = str(Path(tempfile.gettempdir()))
    clean = clean.replace(temp_root, "<temp>")
    clean = clean.replace(temp_root.replace("\\", "/"), "<temp>")
    # Strip any potential tokens or credentials from URLs
    clean = re.sub(r"://[^@\s]+@", "://", clean)
    return clean


def safe_rmtree(path: Path | str) -> None:
    """Robustly remove directory tree on Windows and Unix, clearing read-only flags.

    Includes defensive guard to ensure it only deletes ghostflow temporary workspaces.
    """
    target = Path(path).resolve()
    if not target.exists():
        return

    # Security guard: never delete root, system, user home, or non-temp directories
    try:
        temp_root = Path(tempfile.gettempdir()).resolve()
        if not target.is_relative_to(temp_root) or "ghostflow_remote_" not in target.name:
            return
    except Exception:
        return

    def _remove_readonly(func: Any, pth: str, exc_info: Any) -> None:
        try:
            os.chmod(pth, stat.S_IWRITE)
            func(pth)
        except Exception:
            pass

    try:
        shutil.rmtree(target, onerror=_remove_readonly)
    except Exception:
        # Fallback best-effort
        try:
            shutil.rmtree(target, ignore_errors=True)
        except Exception:
            pass


def _neutralize_symlinks(root: Path) -> int:
    """Detect and remove symlinks that resolve outside the repository root."""
    resolved_root = root.resolve()
    neutralized = 0

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_dir = Path(dirpath)
        # Check directory symlinks
        for d in list(dirnames):
            d_path = current_dir / d
            if d_path.is_symlink():
                try:
                    target = d_path.resolve()
                    if not target.is_relative_to(resolved_root):
                        d_path.unlink()
                        dirnames.remove(d)
                        neutralized += 1
                except Exception:
                    d_path.unlink(missing_ok=True)
                    dirnames.remove(d)
                    neutralized += 1

        # Check file symlinks
        for f in filenames:
            f_path = current_dir / f
            if f_path.is_symlink():
                try:
                    target = f_path.resolve()
                    if not target.is_relative_to(resolved_root):
                        f_path.unlink()
                        neutralized += 1
                except Exception:
                    f_path.unlink(missing_ok=True)
                    neutralized += 1

    return neutralized


def _enforce_resource_limits(
    root: Path,
    max_size_bytes: int | None = None,
    max_single_file_bytes: int | None = None,
    max_files: int | None = None,
) -> tuple[int, int]:
    """Calculate repository size and file count, raising ValueError if exceeded."""
    limit_size = max_size_bytes if max_size_bytes is not None else get_max_repo_size_bytes()
    limit_single_file = max_single_file_bytes if max_single_file_bytes is not None else get_max_single_file_bytes()
    limit_files = max_files if max_files is not None else get_max_file_count()

    total_size = 0
    total_files = 0

    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for f in filenames:
            total_files += 1
            if total_files > limit_files:
                raise ValueError(
                    f"Repository exceeds file limit ({limit_files:,} files). Remote scanning is restricted to lightweight projects."
                )
            f_path = Path(dirpath) / f
            file_size = 0
            try:
                if not f_path.is_symlink():
                    file_size = f_path.stat().st_size
                    total_size += file_size
            except Exception:
                pass

            if file_size > limit_single_file:
                max_mb = limit_single_file // (1024 * 1024)
                raise ValueError(
                    f"Repository contains file '{f}' exceeding the {max_mb} MB single-file limit."
                )

            if total_size > limit_size:
                max_mb = limit_size // (1024 * 1024)
                raise ValueError(
                    f"Repository exceeds size limit ({max_mb} MB). Remote scanning is restricted to lightweight projects."
                )

    return total_files, total_size


def _terminate_process(proc: subprocess.Popen[Any]) -> None:
    """Safely terminate a subprocess and any spawned children."""
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except Exception:
                pass
    except Exception:
        pass


def acquire_remote_repository(
    normalized_url: str,
    target_dir: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """Execute shallow clone into target_dir with hardened security restrictions.

    Security & Isolation measures:
    - shell=False with argument vector.
    - Explicit '--' delimiter prevents flag injection.
    - Disables terminal prompts, credentials, and credential helpers.
    - Strictly restricts protocol to HTTPS (disables file://, ext::, etc.).
    - Disables HTTP redirects to external hosts (http.followRedirects=false).
    - Disables core hooks and Git LFS filters.
    - Disables submodules (--recurse-submodules=no).
    - Disables global/system Git configs.
    - Actively monitors disk usage during acquisition to terminate runaway clones.
    """
    timeout = min(max(timeout_seconds, 0.5), MAX_TIMEOUT_SECONDS)
    max_size_bytes = get_max_repo_size_bytes()

    # Secure environment: no terminal prompt, no custom credential helpers, no system/global configs
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "TEMP": os.environ.get("TEMP", ""),
        "TMP": os.environ.get("TMP", ""),
    }

    # Use NUL on Windows, /dev/null on Unix for hooks path
    hooks_null = "NUL" if os.name == "nt" else "/dev/null"

    cmd = [
        "git",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", f"core.hooksPath={hooks_null}",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.clean=",
        "-c", "filter.lfs.process=",
        "-c", "filter.lfs.required=false",
        "-c", "credential.helper=",
        "-c", "core.fsmonitor=false",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--no-tags",
        "--recurse-submodules=no",
        "--",
        normalized_url,
        str(target_dir),
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Git executable is not available on the server environment.") from exc

    start_time = time.time()
    exceeded_size = False

    while proc.poll() is None:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            _terminate_process(proc)
            raise TimeoutError(
                f"Repository acquisition timed out after {timeout} seconds. The repository may be too large or the network is unreachable."
            )

        # Real-time disk size monitoring during clone acquisition
        if target_dir.exists():
            current_size = 0
            for dirpath, _, filenames in os.walk(target_dir, followlinks=False):
                for f in filenames:
                    try:
                        current_size += (Path(dirpath) / f).stat().st_size
                    except Exception:
                        pass
            if current_size > max_size_bytes:
                exceeded_size = True
                _terminate_process(proc)
                break

        time.sleep(0.2)

    stdout, stderr = proc.communicate()

    if exceeded_size:
        max_mb = max_size_bytes // (1024 * 1024)
        raise ValueError(
            f"Repository exceeds acquisition size limit ({max_mb} MB). Remote scanning is restricted to lightweight projects."
        )

    if proc.returncode != 0:
        err = _sanitize_error(stderr.strip(), target_dir.parent)
        if "could not read Username" in err or "Authentication failed" in err or "not found" in err:
            raise ValueError(
                f"Repository not found or inaccessible: '{normalized_url}'. Please ensure the repository is public and spelled correctly."
            )
        raise RuntimeError(f"Git clone failed (exit code {proc.returncode}): {err}")


def scan_remote_github_repository(
    repo_url: str,
    openapi_path: str | None = None,
    auto_detect_openapi: bool = True,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Securely clone, inspect, and analyze a public GitHub repository.

    Guarantees:
    - Code is never executed.
    - Scanned files are isolated in a temporary directory.
    - Symlink escapes and resource limits are actively checked.
    - Temporary directory is deleted upon completion or failure.
    - Report is marked read_only and is_remote_github.
    """
    owner, repo, normalized_url = validate_github_url(repo_url)

    # Acquire concurrency slot with guaranteed release in finally
    with remote_scan_slot():
        # Create temporary directory with distinct prefix
        temp_workspace_dir = Path(tempfile.mkdtemp(prefix="ghostflow_remote_"))
        # Use deterministic 'repo' directory name to avoid path traversal via repo name
        clone_target = temp_workspace_dir / "repo"

        start_time = time.time()
        try:
            # Step 1: Acquire repository via shallow clone with real-time size limit
            acquire_remote_repository(
                normalized_url=normalized_url,
                target_dir=clone_target,
                timeout_seconds=timeout_seconds,
            )

            # Step 2: Enforce security & resource boundaries
            _neutralize_symlinks(clone_target)
            _enforce_resource_limits(clone_target)

            # Step 3: Run GhostFlow AST static scanner
            report = scan_project(
                project_path=str(clone_target),
                openapi_path=openapi_path,
                auto_detect_openapi=auto_detect_openapi,
                allowed_roots=[clone_target],
            )

            # Step 4: Anonymize paths and attach remote metadata
            # Display project path as public GitHub URL rather than internal temp filesystem path
            report["project_path"] = normalized_url
            report["repo_url"] = normalized_url
            report["owner"] = owner
            report["repo"] = repo
            report["is_remote_github"] = True
            report["read_only"] = True
            report["clone_duration_seconds"] = round(time.time() - start_time, 2)
            report["resource_limits"] = get_remote_resource_limits()

            return report

        except Exception as exc:
            sanitized_msg = _sanitize_error(str(exc), temp_workspace_dir)
            if sanitized_msg != str(exc):
                raise type(exc)(sanitized_msg) from None
            raise

        finally:
            # Step 5: Guaranteed cleanup of temporary workspace
            safe_rmtree(temp_workspace_dir)
