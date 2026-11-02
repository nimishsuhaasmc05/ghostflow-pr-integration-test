"""Build & Dependency static diagnostics for GhostFlow.

BLD001 — Missing Package Dependency in Manifest (package.json)
    Detects third-party npm package imports in frontend code that are absent
    from package.json dependencies, devDependencies, and peerDependencies.

BLD002 — Missing Python Dependency in Requirements / Pyproject
    Detects third-party Python imports in backend code that are absent
    from requirements.txt or pyproject.toml.

BLD003 — Circular Module Dependency
    Detects direct 2-module import cycles (A imports B, B imports A)
    that can cause undefined imports and runtime initialization failures.

Design constraints:
- Never install packages or run package managers.
- Never execute arbitrary scripts.
- Pure static analysis of manifests and import statements.
- can_autofix is always False (diagnostic-only).
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .models import Evidence, Finding

_EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".venv",
    "venv",
    "node_modules",
    ".git",
    "dist",
    "build",
    ".ghostflow",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "coverage",
    ".coverage",
    "htmlcov",
})

_NODE_BUILTINS: frozenset[str] = frozenset({
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
})

_STDLIB_MODULES: frozenset[str] = frozenset(
    getattr(sys, "stdlib_module_names", set()) | {
        "__future__",
        "sys",
        "os",
        "typing",
        "pathlib",
        "re",
        "json",
        "datetime",
        "math",
        "collections",
        "itertools",
        "functools",
        "hashlib",
        "logging",
        "unittest",
        "subprocess",
        "abc",
        "contextlib",
        "dataclasses",
        "enum",
        "io",
        "shutil",
        "tempfile",
        "time",
        "uuid",
    }
)


def _normalise_file(filepath: str) -> str:
    p = filepath.replace("\\", "/").strip()
    return p.split("/")[-1] if "/" in p else p


def _strip_comments(source: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source[i] in ("'", '"', "`"):
            quote = source[i]
            out.append(quote)
            i += 1
            while i < n:
                if source[i] == "\\":
                    out.append(source[i:min(i + 2, n)])
                    i += 2
                    continue
                out.append(source[i])
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        if source[i:i + 2] == "//":
            j = source.find("\n", i)
            if j == -1:
                j = n
            out.append(" " * (j - i))
            i = j
            continue

        if source[i:i + 2] == "/*":
            j = source.find("*/", i + 2)
            if j == -1:
                j = n
            else:
                j += 2
            comment_text = source[i:j]
            out.append("\n" * comment_text.count("\n") + " " * (len(comment_text) - comment_text.count("\n")))
            i = j
            continue

        out.append(source[i])
        i += 1

    return "".join(out)


def _iter_files(root: Path, extensions: tuple[str, ...]) -> list[Path]:
    results: list[Path] = []
    if not root.is_dir():
        return results
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for fname in filenames:
            if fname.lower().endswith(extensions):
                results.append(Path(dirpath) / fname)
    return results


def _is_import_exception_handler(handler: ast.ExceptHandler) -> bool:
    """Check if an except handler catches ImportError, ModuleNotFoundError, Exception, or is bare."""
    if handler.type is None:
        return True
    target_names = {"importerror", "modulenotfounderror", "exception", "baseexception"}
    if isinstance(handler.type, ast.Name):
        return handler.type.id.lower() in target_names
    elif isinstance(handler.type, ast.Tuple):
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name) and elt.id.lower() in target_names:
                return True
    return False


def _is_type_checking_guard(test_node: ast.expr) -> bool:
    """Check if an if-statement tests TYPE_CHECKING."""
    if isinstance(test_node, ast.Name) and test_node.id == "TYPE_CHECKING":
        return True
    if isinstance(test_node, ast.Attribute) and test_node.attr == "TYPE_CHECKING":
        return True
    return False


class PythonImportCollector(ast.NodeVisitor):
    """Collects Python imports with scope and exception guard awareness."""

    def __init__(self) -> None:
        self.imports: list[tuple[str, int, bool, bool]] = []  # (pkg_name, lineno, is_top_level, is_guarded)
        self._guard_depth = 0
        self._scope_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_Try(self, node: ast.Try) -> None:
        has_import_catch = any(_is_import_exception_handler(h) for h in node.handlers)
        if has_import_catch:
            self._guard_depth += 1
            for stmt in node.body:
                self.visit(stmt)
            self._guard_depth -= 1
        else:
            for stmt in node.body:
                self.visit(stmt)
        for h in node.handlers:
            self.visit(h)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_guard(node.test):
            self._guard_depth += 1
            for stmt in node.body:
                self.visit(stmt)
            self._guard_depth -= 1
        else:
            for stmt in node.body:
                self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Import(self, node: ast.Import) -> None:
        is_top = (self._scope_depth == 0 and self._guard_depth == 0)
        is_guarded = (self._guard_depth > 0)
        for alias in node.names:
            top = alias.name.split(".")[0].lower()
            self.imports.append((top, node.lineno, is_top, is_guarded))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        is_top = (self._scope_depth == 0 and self._guard_depth == 0)
        is_guarded = (self._guard_depth > 0)
        if node.level == 0 and node.module:
            top = node.module.split(".")[0].lower()
            self.imports.append((top, node.lineno, is_top, is_guarded))


def _bld001_missing_package_deps(root: Path) -> list[Finding]:
    """Check for external npm imports not declared in package.json."""
    findings: list[Finding] = []
    # Locate package.json across common monorepo root candidates
    pkg_json_candidates = [
        root / "package.json",
        root / "frontend" / "package.json",
        root / "client" / "package.json",
        root / "web" / "package.json",
        root / "ui" / "package.json",
        root / "apps" / "web" / "package.json",
        root / "apps" / "client" / "package.json",
    ]
    pkg_json_files = [p for p in pkg_json_candidates if p.is_file()]
    if not pkg_json_files:
        return findings

    declared_pkgs = set()
    primary_pkg_file = pkg_json_files[0]

    for pfile in pkg_json_files:
        try:
            data = json.loads(pfile.read_text(encoding="utf-8", errors="replace"))
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                sec = data.get(section, {})
                if isinstance(sec, dict):
                    declared_pkgs.update(sec.keys())
        except Exception:
            pass

    import_re = re.compile(
        r"""(?:import|export)\b(?:(?!import|export)[^;])*?\bfrom\s*['"]([^'"]+)['"]""",
        re.MULTILINE
    )

    frontend_root = root / "frontend" / "src"
    if not frontend_root.exists():
        frontend_root = root / "frontend"
    if not frontend_root.exists():
        frontend_root = root / "client" / "src"
    if not frontend_root.exists():
        frontend_root = root / "client"
    if not frontend_root.exists():
        frontend_root = root / "src"
    if not frontend_root.exists():
        frontend_root = root

    fe_files = _iter_files(frontend_root, (".ts", ".tsx", ".js", ".jsx", ".mjs"))
    seen_ids: set[str] = set()

    for f in fe_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        clean = _strip_comments(content)
        lines = content.splitlines()

        for m in import_re.finditer(clean):
            spec = m.group(1).strip()
            # Skip relative or absolute paths, and path aliases (@/, ~/)
            if spec.startswith((".", "/", "@/", "~/")):
                continue
            # Extract package root name (e.g. '@scope/pkg/sub' -> '@scope/pkg', 'lodash/get' -> 'lodash')
            if spec.startswith("@"):
                parts = spec.split("/")
                pkg_name = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else spec
            else:
                pkg_name = spec.split("/")[0]

            if pkg_name in _NODE_BUILTINS or pkg_name.startswith("node:"):
                continue

            if pkg_name not in declared_pkgs:
                lineno = content.count("\n", 0, m.start()) + 1
                snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"import from '{spec}'"
                fid = hashlib.sha1(f"BLD001:{_normalise_file(str(f))}:{lineno}:{pkg_name}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    findings.append(Finding(
                        id=fid,
                        rule_id="BLD001",
                        title=f"Missing dependency '{pkg_name}' in package.json",
                        severity="high",
                        confidence=0.95,
                        category="Build & Dependencies",
                        message=f"'{f.name}' imports package '{pkg_name}', but it is not listed in package.json dependencies.",
                        recommendation=f"Add '{pkg_name}' to package.json dependencies, or remove the unused import.",
                        evidence=[
                            Evidence(role="frontend", file=str(f), line=lineno, source=snippet),
                            Evidence(role="frontend", file=str(primary_pkg_file), line=1, source=f"// {primary_pkg_file.name}"),
                        ],
                        details={"package": pkg_name, "specifier": spec, "file": str(f)},
                    ))

    return findings


def _bld002_missing_python_deps(root: Path) -> list[Finding]:
    """Check for external Python imports not declared in requirements.txt or pyproject.toml."""
    findings: list[Finding] = []

    # Locate all manifests across root and nested server/backend folders
    manifest_candidates = [
        root / "requirements.txt",
        root / "backend" / "requirements.txt",
        root / "server" / "requirements.txt",
        root / "api" / "requirements.txt",
        root / "pyproject.toml",
        root / "backend" / "pyproject.toml",
        root / "server" / "pyproject.toml",
        root / "api" / "pyproject.toml",
    ]
    manifest_files = [p for p in manifest_candidates if p.is_file()]
    if not manifest_files:
        return findings

    declared_pkgs: set[str] = set()
    manifest_evidence_file = str(manifest_files[0])

    for mfile in manifest_files:
        try:
            mcontent = mfile.read_text(encoding="utf-8", errors="replace")
            if mfile.name.endswith(".txt"):
                for line in mcontent.splitlines():
                    line = line.strip().split("#")[0].strip()
                    if line and not line.startswith("-"):
                        pkg = re.split(r"[=<>~!]", line)[0].strip().lower().replace("-", "_")
                        if pkg:
                            declared_pkgs.add(pkg)
            elif mfile.name.endswith(".toml"):
                for m in re.finditer(r'["\']([a-zA-Z0-9_\-\.]+)(?:[=<>~!]|\s*["\'])', mcontent):
                    pkg = m.group(1).lower().replace("-", "_")
                    declared_pkgs.add(pkg)
        except OSError:
            pass

    # Discover local top packages so we don't flag internal modules
    backend_root = root / "backend"
    if not backend_root.exists():
        backend_root = root / "server"
    if not backend_root.exists():
        backend_root = root

    local_pkgs = {p.name.replace(".py", "").lower().replace("-", "_") for p in backend_root.iterdir() if not p.name.startswith(".")}
    local_pkgs.update({p.name.replace(".py", "").lower().replace("-", "_") for p in root.iterdir() if not p.name.startswith(".")})

    py_files = _iter_files(backend_root, (".py",))
    seen_ids: set[str] = set()

    # Map popular import names to canonical package names
    KNOWN_MAPPINGS = {
        "fastapi": "fastapi",
        "pydantic": "pydantic",
        "uvicorn": "uvicorn",
        "httpx": "httpx",
        "starlette": "starlette",
        "requests": "requests",
        "pytest": "pytest",
        "jwt": "pyjwt",
        "yaml": "pyyaml",
        "cv2": "opencv_python",
        "bs4": "beautifulsoup4",
        "dotenv": "python_dotenv",
    }

    for f in py_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(f))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        lines = content.splitlines()

        collector = PythonImportCollector()
        collector.visit(tree)

        for top, lineno, is_top, is_guarded in collector.imports:
            # Skip stdlib and internal packages
            if top in _STDLIB_MODULES or top in local_pkgs:
                continue

            # Skip imports with explicit exception guards (e.g. try: import foo except ImportError:)
            if is_guarded:
                continue

            canonical_pkg = KNOWN_MAPPINGS.get(top, top).replace("-", "_")
            if canonical_pkg not in declared_pkgs and top not in declared_pkgs:
                fid = hashlib.sha1(f"BLD002:{_normalise_file(str(f))}:{lineno}:{top}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"import {top}"

                    if is_top:
                        confidence = 0.95
                        severity = "medium"
                        message = f"'{f.name}' imports package '{top}', but it is not listed in requirements.txt or pyproject.toml."
                        uncertainty = None
                    else:
                        confidence = 0.60
                        severity = "low"
                        message = f"'{f.name}' imports package '{top}' inside function scope, but it is not declared in requirements.txt or pyproject.toml (deferred import)."
                        uncertainty = "Deferred import inside function scope may be an optional adapter or lazy-loaded dependency."

                    details_dict = {"package": top, "file": str(f), "is_top_level": is_top}
                    if uncertainty:
                        details_dict["uncertainty"] = uncertainty

                    findings.append(Finding(
                        id=fid,
                        rule_id="BLD002",
                        title=f"Missing Python dependency '{top}' in requirements manifest",
                        severity=severity,
                        confidence=confidence,
                        category="Build & Dependencies",
                        message=message,
                        recommendation=f"Add '{canonical_pkg}' to requirements.txt or pyproject.toml dependencies.",
                        evidence=[
                            Evidence(role="backend", file=str(f), line=lineno, source=snippet),
                            Evidence(role="backend", file=manifest_evidence_file, line=1, source=f"# {Path(manifest_evidence_file).name}"),
                        ],
                        details=details_dict,
                    ))

    return findings


def _bld003_circular_dependencies(root: Path) -> list[Finding]:
    """Detect direct 2-file circular imports (A imports B, B imports A)."""
    findings: list[Finding] = []
    # Build relative import mapping for Python and JS/TS
    files = _iter_files(root, (".py", ".ts", ".tsx", ".js", ".jsx"))
    rel_imports: dict[Path, set[Path]] = {}

    for f in files:
        imports_set: set[Path] = set()
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        importer_dir = f.parent

        if f.suffix == ".py":
            try:
                tree = ast.parse(content, filename=str(f))
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.level > 0:
                        target_dir = importer_dir
                        for _ in range(node.level - 1):
                            target_dir = target_dir.parent
                        if node.module:
                            cand = target_dir.joinpath(*node.module.split(".")).with_suffix(".py")
                            if cand.is_file():
                                imports_set.add(cand.resolve())
            except Exception:
                pass
        else:
            clean = _strip_comments(content)
            for m in re.finditer(r"""\b(?:import|export)\b(?:(?!import|export)[^;])*?\bfrom\s*['"](\.[^'"]+)['"]""", clean):
                spec = m.group(1)
                for ext in ("", ".ts", ".tsx", ".js", ".jsx"):
                    cand = (importer_dir / f"{spec}{ext}").resolve()
                    if cand.is_file():
                        imports_set.add(cand)
                        break

        rel_imports[f.resolve()] = imports_set

    seen_pairs: set[tuple[Path, Path]] = set()

    for file_a, targets_a in rel_imports.items():
        for file_b in targets_a:
            if file_b in rel_imports and file_a in rel_imports[file_b] and file_a != file_b:
                pair = tuple(sorted([file_a, file_b]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    fid = hashlib.sha1(f"BLD003:{_normalise_file(str(file_a))}:{_normalise_file(str(file_b))}".encode()).hexdigest()[:12]
                    findings.append(Finding(
                        id=fid,
                        rule_id="BLD003",
                        title=f"Circular dependency between '{file_a.name}' and '{file_b.name}'",
                        severity="medium",
                        confidence=0.92,
                        category="Build & Dependencies",
                        message=f"Direct circular dependency detected: '{file_a.name}' imports '{file_b.name}' and '{file_b.name}' imports '{file_a.name}'. This can lead to undefined imports and module initialization crashes.",
                        recommendation="Refactor shared types or functions into a separate utility module to break the circular dependency cycle.",
                        evidence=[
                            Evidence(role="frontend" if file_a.suffix != ".py" else "backend", file=str(file_a), line=1, source=f"// imports {file_b.name}"),
                            Evidence(role="frontend" if file_b.suffix != ".py" else "backend", file=str(file_b), line=1, source=f"// imports {file_a.name}"),
                        ],
                        details={"file_a": str(file_a), "file_b": str(file_b)},
                    ))

    return findings


def analyze_build_diagnostics(root: Path) -> list[Finding]:
    """Run build and dependency diagnostics (BLD001, BLD002, BLD003) across the project."""
    findings: list[Finding] = []
    try:
        findings.extend(_bld001_missing_package_deps(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"BLD001 failed: {exc}", stacklevel=2)

    try:
        findings.extend(_bld002_missing_python_deps(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"BLD002 failed: {exc}", stacklevel=2)

    try:
        findings.extend(_bld003_circular_dependencies(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"BLD003 failed: {exc}", stacklevel=2)

    return findings
