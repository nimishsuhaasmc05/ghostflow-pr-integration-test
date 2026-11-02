"""Backend static diagnostics for GhostFlow.

BE001 — Unresolved Local Python Imports
    Detects unresolved local Python imports and package references that cannot
    be resolved to an existing Python module (.py) or package directory on disk,
    as well as path traversal attempts outside the scanned project root.

BE002 — Missing Symbol in Local Python Module
    Detects imported functions, classes, or attributes from local modules
    that are not defined in the target module.

BE003 — Unbound Route Path Parameter in Handler Signature
    Detects FastAPI/Starlette route declarations containing path parameters
    (e.g., '{item_id}') that are missing from the handler function's arguments.

Design constraints:
- Never execute scanned source code.
- Never import project modules at runtime or use importlib.
- Never install packages automatically.
- Never follow symlinks outside the approved project root.
- Pure static analysis using Python AST and filesystem resolution.
- Distinguishes local modules from standard library and third-party dependencies.
- Suppresses external/ambiguous imports to avoid false positives.
- can_autofix is always False (diagnostic-only).
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Any

from .models import Evidence, Finding

# ---------------------------------------------------------------------------
# Exclusion helpers and constants
# ---------------------------------------------------------------------------

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

# Standard library module names (Python 3.10+ sys.stdlib_module_names with common fallbacks)
_STDLIB_MODULES: frozenset[str] = frozenset(
    getattr(sys, "stdlib_module_names", set()) | {
        "__future__",
        "_thread",
        "builtins",
        "posix",
        "nt",
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
    }
)


def _is_within_root(target: Path, root_resolved: Path) -> bool:
    """Return True if target resolves strictly within root_resolved."""
    try:
        resolved = target.resolve()
        return resolved == root_resolved or root_resolved in resolved.parents
    except (OSError, RuntimeError, ValueError):
        return False


def _iter_python_files(root: Path) -> list[Path]:
    """Yield all .py files under root, skipping excluded directories without following symlinks."""
    results: list[Path] = []
    if not root.is_dir():
        return results
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda _: None):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                results.append(Path(dirpath) / fname)
    return sorted(results)


def _normalise_file(filepath: str) -> str:
    """Normalize file path for stable hash generation across platforms."""
    p = filepath.replace("\\", "/").strip()
    return p.split("/")[-1] if "/" in p else p


def _get_search_roots(root: Path, importer_path: Path) -> list[Path]:
    """Compute candidate Python search roots for the given importer file.
    
    Includes project root, conventional source directories (backend, src, app),
    and directory ancestors of the importer file up to root.
    """
    root_resolved = root.resolve()
    importer_resolved = importer_path.resolve()
    candidates: list[Path] = [root_resolved]

    for sub in ("backend", "src", "app"):
        cand = root_resolved / sub
        if cand.is_dir():
            candidates.append(cand)
            for sub2 in ("src", "scanner", "app"):
                cand2 = cand / sub2
                if cand2.is_dir():
                    candidates.append(cand2)

    # Ancestors of the importing file up to project root
    curr = importer_resolved.parent
    while _is_within_root(curr, root_resolved):
        candidates.append(curr)
        if curr == root_resolved:
            break
        curr = curr.parent

    seen: set[Path] = set()
    roots: list[Path] = []
    for c in candidates:
        if c not in seen and c.is_dir() and _is_within_root(c, root_resolved):
            seen.add(c)
            roots.append(c)
    return roots


def _dir_has_python(directory: Path) -> bool:
    """Return True if directory contains at least one .py file, skipping excluded directories."""
    if not directory.is_dir():
        return False
    try:
        for child in directory.iterdir():
            if child.name in _EXCLUDED_DIRS:
                continue
            if child.is_file() and child.suffix == ".py":
                return True
            if child.is_dir() and not child.is_symlink():
                if _dir_has_python(child):
                    return True
    except OSError:
        pass
    return False


def _is_local_top_package(name: str, search_roots: list[Path]) -> bool:
    """Check if top-level package name exists in any search root as a file or directory package."""
    for r in search_roots:
        cand_file = r / f"{name}.py"
        if cand_file.is_file():
            return True
        cand_dir = r / name
        if cand_dir.is_dir() and ((cand_dir / "__init__.py").is_file() or _dir_has_python(cand_dir)):
            return True
    return False


def _get_module_symbols(file_path: Path) -> tuple[set[str], bool]:
    """Extract declared top-level symbols from a Python source file.
    
    Returns (symbols, has_dynamic) where has_dynamic is True if wildcard imports
    or dynamic attribute lookups (__getattr__) are present.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return set(), True

    symbols: set[str] = set()
    has_dynamic = False

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.add(node.name)
            if node.name == "__getattr__":
                has_dynamic = True
        elif isinstance(node, ast.ClassDef):
            symbols.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    symbols.add(t.id)
                    if t.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                symbols.add(elt.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                symbols.add(node.target.id)
        elif isinstance(node, ast.Import):
            for a in node.names:
                symbols.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    has_dynamic = True
                else:
                    symbols.add(a.asname or a.name)

    return symbols, has_dynamic


# ---------------------------------------------------------------------------
# Import Resolution Logic
# ---------------------------------------------------------------------------

def _resolve_relative_import(
    importer_file: Path,
    level: int,
    module: str | None,
    imported_names: list[str],
    root_resolved: Path,
) -> tuple[str, str | None]:
    """Resolve a relative import against the project root.
    
    Returns (status, detail):
      - ("ok", resolved_path)
      - ("path_traversal", escaped_path)
      - ("missing_module", missing_specifier)
    """
    importer_resolved = importer_file.resolve()
    base_dir = importer_resolved.parent
    for _ in range(level - 1):
        base_dir = base_dir.parent

    # Path traversal check: did relative navigation leave the approved project root?
    if not _is_within_root(base_dir, root_resolved):
        return ("path_traversal", str(base_dir))

    # Case 1: module is explicitly specified (e.g., `from .utils import helper`)
    if module:
        parts = module.split(".")
        cand_file = base_dir.joinpath(*parts).with_suffix(".py")
        if cand_file.is_file():
            if not _is_within_root(cand_file, root_resolved):
                return ("path_traversal", str(cand_file))
            return ("ok", str(cand_file))

        cand_dir = base_dir.joinpath(*parts)
        if cand_dir.is_dir():
            if not _is_within_root(cand_dir, root_resolved):
                return ("path_traversal", str(cand_dir))
            cand_init = cand_dir / "__init__.py"
            if cand_init.is_file() or _dir_has_python(cand_dir):
                return ("ok", str(cand_dir))

        return ("missing_module", f"{'.' * level}{module}")

    # Case 2: module is None (e.g., `from . import helper`)
    # Each imported name is either a submodule/package or symbol in base_dir/__init__.py
    if not imported_names:
        return ("ok", str(base_dir))

    init_file = base_dir / "__init__.py"
    init_symbols: set[str] = set()
    init_dynamic: bool = False
    if init_file.is_file():
        init_symbols, init_dynamic = _get_module_symbols(init_file)

    for name in imported_names:
        cand_file = base_dir / f"{name}.py"
        if cand_file.is_file():
            if not _is_within_root(cand_file, root_resolved):
                return ("path_traversal", str(cand_file))
            continue

        cand_dir = base_dir / name
        if cand_dir.is_dir() and ((cand_dir / "__init__.py").is_file() or _dir_has_python(cand_dir)):
            if not _is_within_root(cand_dir, root_resolved):
                return ("path_traversal", str(cand_dir))
            continue

        # If base_dir has __init__.py and defines the symbol (or has dynamic exports)
        if init_file.is_file() and (init_dynamic or name in init_symbols):
            continue

        return ("missing_module", f"{'.' * level}{name}")

    return ("ok", str(base_dir))


def _resolve_absolute_import(
    module_str: str,
    imported_names: list[str],
    search_roots: list[Path],
    root_resolved: Path,
) -> tuple[str, str | None]:
    """Resolve an absolute import against project search roots.
    
    Returns (status, detail):
      - ("ok", resolved_path)
      - ("suppressed", reason)   # stdlib or third-party dependency
      - ("missing_module", missing_specifier)
      - ("path_traversal", escaped_path)
    """
    if not module_str:
        return ("suppressed", "empty")

    parts = module_str.split(".")
    top = parts[0]

    # Suppress standard library modules
    if top in _STDLIB_MODULES:
        return ("suppressed", "stdlib")

    # If the top-level package is not found locally in any search root,
    # treat it as an external/third-party package and suppress.
    if not _is_local_top_package(top, search_roots):
        return ("suppressed", "third_party")

    # The top-level package exists locally. Resolve the requested module/submodule path.
    for r in search_roots:
        cand_file = r.joinpath(*parts).with_suffix(".py")
        if cand_file.is_file():
            if not _is_within_root(cand_file, root_resolved):
                return ("path_traversal", str(cand_file))
            return ("ok", str(cand_file))

        cand_dir = r.joinpath(*parts)
        if cand_dir.is_dir():
            if not _is_within_root(cand_dir, root_resolved):
                return ("path_traversal", str(cand_dir))
            cand_init = cand_dir / "__init__.py"
            if cand_init.is_file():
                # Regular package: if imported_names given, check submodules or __init__ symbols
                if imported_names:
                    pkg_symbols, pkg_dynamic = _get_module_symbols(cand_init)
                    all_found = True
                    for sym in imported_names:
                        sub_file = cand_dir / f"{sym}.py"
                        sub_pkg = cand_dir / sym
                        if sub_file.is_file() or (sub_pkg.is_dir() and _dir_has_python(sub_pkg)):
                            continue
                        if pkg_dynamic or sym in pkg_symbols:
                            continue
                        all_found = False
                        break
                    if all_found:
                        return ("ok", str(cand_dir))
                else:
                    return ("ok", str(cand_dir))
            elif _dir_has_python(cand_dir):
                # PEP 420 namespace package: check if submodules match imported_names
                if imported_names:
                    all_found = True
                    for sym in imported_names:
                        sub_file = cand_dir / f"{sym}.py"
                        sub_pkg = cand_dir / sym
                        if sub_file.is_file() or (sub_pkg.is_dir() and _dir_has_python(sub_pkg)):
                            continue
                        all_found = False
                        break
                    if all_found:
                        return ("ok", str(cand_dir))
                else:
                    return ("ok", str(cand_dir))

    return ("missing_module", module_str)


# ---------------------------------------------------------------------------
# Main Analyzer Entrypoint
# ---------------------------------------------------------------------------

def analyze_backend_diagnostics(root: Path) -> list[Finding]:
    """Analyze Python files in root for unresolved imports (BE001).
    
    Pure static analysis using Python AST. Never imports modules or executes code.
    """
    root_resolved = root.resolve()
    py_files = _iter_python_files(root_resolved)
    findings: list[Finding] = []
    seen_ids: set[str] = set()

    for importer in py_files:
        try:
            content = importer.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(importer))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue

        lines = content.splitlines()
        search_roots = _get_search_roots(root_resolved, importer)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    import_spec = alias.name
                    lineno = node.lineno
                    status, detail = _resolve_absolute_import(
                        module_str=import_spec,
                        imported_names=[],
                        search_roots=search_roots,
                        root_resolved=root_resolved,
                    )
                    if status in ("missing_module", "path_traversal"):
                        source_snippet = (
                            lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"import {import_spec}"
                        )
                        _record_finding(
                            findings=findings,
                            seen_ids=seen_ids,
                            importer=importer,
                            lineno=lineno,
                            import_spec=import_spec,
                            source_snippet=source_snippet,
                            status=status,
                            detail=detail,
                        )

            elif isinstance(node, ast.ImportFrom):
                lineno = node.lineno
                imported_names = [a.name for a in node.names if a.name != "*"]
                if node.level > 0:
                    import_spec = ("." * node.level) + (node.module or "")
                    status, detail = _resolve_relative_import(
                        importer_file=importer,
                        level=node.level,
                        module=node.module,
                        imported_names=imported_names,
                        root_resolved=root_resolved,
                    )
                    if node.module is None and detail:
                        import_spec = detail
                else:
                    import_spec = node.module or ""
                    status, detail = _resolve_absolute_import(
                        module_str=import_spec,
                        imported_names=imported_names,
                        search_roots=search_roots,
                        root_resolved=root_resolved,
                    )

                if status in ("missing_module", "path_traversal"):
                    source_snippet = (
                        lines[lineno - 1].strip()
                        if 0 < lineno <= len(lines)
                        else f"from {import_spec} import ..."
                    )
                    _record_finding(
                        findings=findings,
                        seen_ids=seen_ids,
                        importer=importer,
                        lineno=lineno,
                        import_spec=import_spec,
                        source_snippet=source_snippet,
                        status=status,
                        detail=detail,
                    )
                elif status == "ok" and detail and detail.endswith(".py"):
                    target_file = Path(detail)
                    if target_file.is_file() and target_file.resolve() != importer.resolve():
                        target_symbols, has_dynamic = _get_module_symbols(target_file)
                        if not has_dynamic and target_symbols:
                            for sym in imported_names:
                                if sym not in target_symbols and not (target_file.name == "__init__.py" and (target_file.parent / f"{sym}.py").is_file()):
                                    fid = hashlib.sha1(f"BE002:{_normalise_file(str(importer))}:{lineno}:{sym}".encode()).hexdigest()[:12]
                                    if fid not in seen_ids:
                                        seen_ids.add(fid)
                                        source_snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"from {import_spec} import {sym}"
                                        findings.append(Finding(
                                            id=fid,
                                            rule_id="BE002",
                                            title=f"Missing symbol '{sym}' in local module '{target_file.name}'",
                                            severity="high",
                                            confidence=0.92,
                                            category="Backend Diagnostics",
                                            message=f"'{importer.name}' imports '{sym}' from local module '{target_file.name}', but '{target_file.name}' does not define '{sym}'.",
                                            recommendation=f"Define '{sym}' in '{target_file.name}', or update the import in '{importer.name}'.",
                                            evidence=[
                                                Evidence(role="backend", file=str(importer), line=lineno, source=source_snippet),
                                                Evidence(role="backend", file=str(target_file), line=1, source=f"# Target module {target_file.name}"),
                                            ],
                                            details={"symbol": sym, "module": import_spec, "target_file": str(target_file)},
                                        ))

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        if dec.func.attr.lower() in ("get", "post", "put", "delete", "patch", "options", "head", "websocket"):
                            route_path = None
                            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                                route_path = dec.args[0].value
                            else:
                                for kw in dec.keywords:
                                    if kw.arg == "path" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                        route_path = kw.value.value
                                        break
                            if route_path and "{" in route_path:
                                path_params = re.findall(r"\{([^{}]+)\}", route_path)
                                if path_params and not node.args.vararg and not node.args.kwarg:
                                    func_args = {arg.arg for arg in node.args.args} | {arg.arg for arg in node.args.kwonlyargs}
                                    for p in path_params:
                                        if p not in func_args:
                                            fid = hashlib.sha1(f"BE003:{_normalise_file(str(importer))}:{node.lineno}:{p}".encode()).hexdigest()[:12]
                                            if fid not in seen_ids:
                                                seen_ids.add(fid)
                                                source_snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else f"def {node.name}(...)"
                                                findings.append(Finding(
                                                    id=fid,
                                                    rule_id="BE003",
                                                    title=f"Path parameter '{p}' missing from handler '{node.name}'",
                                                    severity="high",
                                                    confidence=0.96,
                                                    category="Backend Diagnostics",
                                                    message=f"Route path '{route_path}' specifies path parameter '{{{p}}}', but handler function '{node.name}' does not include '{p}' in its arguments. FastAPI/Starlette will fail to bind this parameter.",
                                                    recommendation=f"Add '{p}' as a parameter to function '{node.name}'.",
                                                    evidence=[
                                                        Evidence(role="backend", file=str(importer), line=node.lineno, source=source_snippet),
                                                    ],
                                                    details={"parameter": p, "route_path": route_path, "function": node.name},
                                                ))

    return findings


def _record_finding(
    findings: list[Finding],
    seen_ids: set[str],
    importer: Path,
    lineno: int,
    import_spec: str,
    source_snippet: str,
    status: str,
    detail: str | None,
) -> None:
    """Construct and append a BE001 Finding if not already recorded."""
    fid = hashlib.sha1(
        f"BE001:{_normalise_file(str(importer))}:{lineno}:{import_spec}".encode()
    ).hexdigest()[:12]

    if fid in seen_ids:
        return
    seen_ids.add(fid)

    if status == "path_traversal":
        title = f"Relative import '{import_spec}' traverses outside project"
        severity = "high"
        confidence = 0.95
        message = (
            f"The relative import '{import_spec}' in {importer.name} (line {lineno}) "
            f"attempts to reference a module outside the project root boundary. "
            f"This creates security risks and will fail in sandboxed or container builds."
        )
        recommendation = (
            f"Update '{import_spec}' to reference a module within the project boundary, "
            f"or install and import it as a standard package."
        )
        issue_type = "path_traversal"
    else:  # missing_module
        title = f"Unresolved Python import '{import_spec}'"
        severity = "high"
        confidence = 0.85
        message = (
            f"Cannot resolve local Python import '{import_spec}' from {importer.name} (line {lineno}). "
            f"No matching Python module (.py) or package directory was found."
        )
        recommendation = (
            f"Verify that the target module or package exists and that the import path is spelled correctly: "
            f"'{import_spec}'. If the module was moved, renamed, or deleted, update this import."
        )
        issue_type = "missing_module"

    evidence = [
        Evidence(
            role="backend",
            file=str(importer),
            line=lineno,
            source=source_snippet,
        )
    ]

    findings.append(
        Finding(
            id=fid,
            rule_id="BE001",
            title=title,
            severity=severity,
            confidence=confidence,
            category="Backend Diagnostics",
            message=message,
            recommendation=recommendation,
            evidence=evidence,
            details={
                "import_spec": import_spec,
                "importer_file": str(importer),
                "issue_type": issue_type,
                "actual_target": detail,
            },
        )
    )
