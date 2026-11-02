"""Frontend static diagnostics for GhostFlow.

FE001 — Unresolved Relative Imports
    Detects relative JavaScript/TypeScript imports that cannot be resolved
    to an existing file or directory index on disk, case-sensitive mismatches,
    or path traversal attempts outside the scanned project root.

FE002 — Missing Named Export in Local Module
    Detects named imports from an existing local module that does not export
    the requested symbol.

FE003 — Missing Default Export in Local Module
    Detects default imports from an existing local module that only defines
    named exports and has no default export.

FE004 — Un-interpolated Path Parameter Placeholder
    Detects frontend HTTP client calls (fetch/axios/apiClient) using literal
    single/double quotes with un-interpolated parameter placeholders like '{id}'.

Design constraints:
- Never execute scanned source code.
- Never install packages automatically.
- Never follow symlinks outside the approved project root.
- Pure static analysis using regex and filesystem resolution.
- can_autofix is always False (diagnostic-only in Milestone 2 / Phase 3).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from .models import Evidence, Finding
from .monorepo import discover_monorepo
from .tsconfig_resolver import get_resolver

# ---------------------------------------------------------------------------
# Exclusion helpers
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

# Scanned importer extensions
_IMPORTER_EXTENSIONS: tuple[str, ...] = (
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
)

# Supported candidate code extensions (in resolution order)
_CODE_EXTENSIONS: tuple[str, ...] = (
    ".ts",
    ".tsx",
    ".d.ts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".json",
)

# Common asset and style extensions
_ASSET_EXTENSIONS: tuple[str, ...] = (
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".wasm",
)

# TS ESM extension mapping: when code imports "./foo.js", the on-disk source
# file in TypeScript is often "./foo.ts" or "./foo.tsx".
_TS_ESM_REWRITES: dict[str, tuple[str, ...]] = {
    ".js": (".ts", ".tsx", ".d.ts"),
    ".jsx": (".tsx",),
    ".mjs": (".mts",),
    ".cjs": (".cts",),
}


def _is_excluded_dir(path: Path) -> bool:
    """Return True if any part of the path is an excluded directory name."""
    return any(part in _EXCLUDED_DIRS for part in path.parts)


def _iter_frontend_files(root: Path) -> list[Path]:
    """Yield source files under root, skipping excluded directories without following symlinks."""
    import os
    results: list[Path] = []
    if not root.is_dir():
        return results
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda _: None):
        # Prune excluded directories in-place so os.walk does not descend into them
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _IMPORTER_EXTENSIONS:
                results.append(Path(dirpath) / fname)
    return sorted(results)


def _normalise_file(filepath: str) -> str:
    """Normalize file path for stable hash generation across platforms."""
    p = filepath.replace("\\", "/").strip()
    return p.split("/")[-1] if "/" in p else p


# ---------------------------------------------------------------------------
# Comment and String Guards
# ---------------------------------------------------------------------------


def _strip_comments(source: str) -> str:
    """Replace comments with whitespace to preserve exact character and line counts."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        # String literal guard: do not strip // or /* inside quotes
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


def _is_inside_string(source: str, offset: int) -> bool:
    """Return True if character offset is inside an unclosed string literal in source."""
    in_quote: str | None = None
    i = 0
    n = min(offset, len(source))
    while i < n:
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if in_quote:
            if ch == in_quote:
                in_quote = None
        else:
            if ch in ("'", '"', "`"):
                in_quote = ch
        i += 1
    return in_quote is not None


# ---------------------------------------------------------------------------
# Static Import Extraction
# ---------------------------------------------------------------------------

# Pattern matching:
# 1. import ... from '...' or export ... from '...'
# 2. Side-effect import '...'
# 3. Dynamic import('...') or require('...')
# 4. Dynamic import(`...`) or require(`...`) with static template string (no ${...})
_STATIC_IMPORT_RE = re.compile(
    r"""(?:"""
    r"""\b(?:import|export)\b(?:(?!import|export)[^;])*?\bfrom\s*['"]([^'"]+)['"]"""
    r"""|^\s*import\s+['"]([^'"]+)['"]"""
    r"""|\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|\b(?:import|require)\s*\(\s*`([^`$]+)`\s*\)"""
    r""")""",
    re.MULTILINE
)


def _extract_relative_imports(content: str) -> list[tuple[str, int, str]]:
    """Extract import specifiers (relative and aliased) from source content.

    Returns list of (import_specifier, line_number, source_line_snippet).
    """
    clean = _strip_comments(content)
    raw_lines = content.splitlines()
    results: list[tuple[str, int, str]] = []

    for m in _STATIC_IMPORT_RE.finditer(clean):
        # Guard: verify the match start is not inside a string literal
        if _is_inside_string(content, m.start()):
            continue

        spec = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        if not spec:
            continue

        # Calculate exact 1-based line number from match offset
        lineno = content.count("\n", 0, m.start()) + 1
        source_snippet = raw_lines[lineno - 1].strip() if 0 < lineno <= len(raw_lines) else ""
        results.append((spec, lineno, source_snippet))

    return results


# Detailed import pattern matching named and default imports
_DETAILED_IMPORT_RE = re.compile(
    r"""(?:"""
    r"""import\s+(?:type\s+)?(?:(?P<default>[A-Za-z_$][A-Za-z0-9_$]*)\s*,?\s*)?(?:\{(?P<named>[^}]+)\})?\s*from\s*['"](?P<spec>[^'"]+)['"]"""
    r"""|export\s*\{(?P<exported>[^}]+)\}\s*from\s*['"](?P<export_spec>[^'"]+)['"]"""
    r""")""",
    re.MULTILINE
)

# Un-interpolated path parameter pattern in frontend fetch/axios calls
_UNINTERPOLATED_PARAM_RE = re.compile(
    r"""\b(?:fetch|axios(?:\.[a-z]+)?|apiClient(?:\.[a-z]+)?)\s*\(\s*['"]([^'"]*\{[a-zA-Z0-9_]+\}[^'"]*)['"]""",
    re.MULTILINE
)


def _extract_detailed_imports(content: str) -> list[dict[str, Any]]:
    """Extract detailed named and default imports from source content."""
    clean = _strip_comments(content)
    raw_lines = content.splitlines()
    results: list[dict[str, Any]] = []

    for m in _DETAILED_IMPORT_RE.finditer(clean):
        if _is_inside_string(content, m.start()):
            continue

        spec = m.group("spec") or m.group("export_spec")
        if not spec:
            continue

        lineno = content.count("\n", 0, m.start()) + 1
        source_snippet = raw_lines[lineno - 1].strip() if 0 < lineno <= len(raw_lines) else ""

        default_name = m.group("default")
        named_raw = m.group("named") or m.group("exported")
        named_symbols: list[str] = []
        if named_raw:
            for part in named_raw.split(","):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("type "):
                    part = part[5:].strip()
                orig_name = part.split(" as ")[0].strip()
                if orig_name:
                    named_symbols.append(orig_name)

        results.append({
            "spec": spec,
            "lineno": lineno,
            "source": source_snippet,
            "default": default_name,
            "named": named_symbols,
        })

    return results


def _extract_module_exports(content: str) -> tuple[set[str], bool, bool]:
    """Extract exported symbol names from JS/TS module content.

    Returns:
        (exported_names, has_default_export, is_indeterminate)
    """
    clean = _strip_comments(content)
    # If module re-exports everything or uses commonjs, mark indeterminate
    if re.search(r'\bexport\s*\*\s*from\b', clean) or re.search(r'\b(?:module\.exports|exports\.)\b', clean):
        return (set(), False, True)

    has_default = bool(re.search(r'\bexport\s+default\b', clean))
    exports: set[str] = set()

    for m in re.finditer(r'\bexport\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)', clean):
        exports.add(m.group(1))
    for m in re.finditer(r'\bexport\s+class\s+([A-Za-z0-9_$]+)', clean):
        exports.add(m.group(1))
    for m in re.finditer(r'\bexport\s+(?:const|let|var)\s+([A-Za-z0-9_$]+)', clean):
        exports.add(m.group(1))
    for m in re.finditer(r'\bexport\s+(?:type|interface|enum)\s+([A-Za-z0-9_$]+)', clean):
        exports.add(m.group(1))
    for m in re.finditer(r'\bexport\s*\{([^}]+)\}', clean):
        for part in m.group(1).split(','):
            part = part.strip()
            if not part:
                continue
            if ' as ' in part:
                exp_name = part.split(' as ')[1].strip()
            else:
                exp_name = part
            if exp_name == 'default':
                has_default = True
            else:
                exports.add(exp_name)

    return (exports, has_default, False)


# ---------------------------------------------------------------------------
# Path & Case-Sensitive Resolution Engine
# ---------------------------------------------------------------------------


def _check_exact_casing(base_dir: Path, rel_spec: str, expected_filename: str) -> tuple[bool, str | None]:
    """Verify that every segment in rel_spec matches the on-disk casing exactly.

    Returns:
        (True, None) if casing matches exactly.
        (False, actual_name) if a casing mismatch is detected.
    """
    current = base_dir
    parts = list(Path(rel_spec).parts)
    if not parts:
        return (True, None)

    for idx, seg in enumerate(parts):
        if seg in (".", ""):
            continue
        if seg == "..":
            current = current.parent
            continue

        is_last = (idx == len(parts) - 1)
        if not current.is_dir():
            return (False, None)

        try:
            entries = {entry.name: entry for entry in current.iterdir()}
        except OSError:
            return (True, None)  # Graceful fallback on unreadable directory

        target_name = expected_filename if is_last else seg

        # 1. Exact match
        if target_name in entries:
            current = current / target_name
            continue

        # 2. Case-insensitive match -> case mismatch defect
        for name in entries:
            if name.lower() == target_name.lower():
                return (False, name)

        return (False, None)

    return (True, None)


def _is_within_root(path: Path, root_resolved: Path) -> bool:
    """Return True if path resolves strictly within root_resolved, without escaping via symlinks."""
    try:
        path.resolve().relative_to(root_resolved)
        return True
    except (ValueError, RuntimeError, OSError):
        return False


def _resolve_relative_import(
    importer_path: Path,
    import_spec: str,
    project_root: Path,
) -> tuple[str, str | None]:
    """Resolve a relative import against the filesystem.

    Returns a tuple of (status, details):
    - ("resolved", resolved_path_str)
    - ("case_mismatch", actual_casing_name)
    - ("path_traversal", None)
    - ("missing_module", None)
    - ("missing_asset", None)
    """
    importer_dir = importer_path.parent
    root_resolved = project_root.resolve()

    # 1. Path traversal and symlink boundary check
    try:
        cand_base = (importer_dir / import_spec).resolve()
        cand_base.relative_to(root_resolved)
    except (ValueError, RuntimeError):
        # Traverses outside project_root or broken recursive symlink
        return ("path_traversal", None)

    # 2. Check candidate targets in order of priority:
    # A) Exact file as written (e.g. ./styles.css or ./module.ts)
    raw_cand = importer_dir / import_spec
    if raw_cand.is_file():
        if not _is_within_root(raw_cand, root_resolved):
            return ("path_traversal", None)
        case_ok, actual_name = _check_exact_casing(importer_dir, import_spec, raw_cand.name)
        if case_ok:
            return ("resolved", str(raw_cand))
        return ("case_mismatch", actual_name)

    # B) Extensionless module: test code extensions
    for ext in _CODE_EXTENSIONS:
        cand = importer_dir / f"{import_spec}{ext}"
        if cand.is_file():
            if not _is_within_root(cand, root_resolved):
                return ("path_traversal", None)
            case_ok, actual_name = _check_exact_casing(importer_dir, import_spec, cand.name)
            if case_ok:
                return ("resolved", str(cand))
            return ("case_mismatch", actual_name)

    # C) Directory index resolution
    if raw_cand.is_dir():
        if not _is_within_root(raw_cand, root_resolved):
            return ("path_traversal", None)
        for ext in _CODE_EXTENSIONS:
            index_cand = raw_cand / f"index{ext}"
            if index_cand.is_file():
                if not _is_within_root(index_cand, root_resolved):
                    return ("path_traversal", None)
                # Check casing of the directory segment first
                case_ok, actual_dir = _check_exact_casing(importer_dir, import_spec, raw_cand.name)
                if not case_ok and actual_dir:
                    return ("case_mismatch", actual_dir)
                # Then check index file casing
                try:
                    index_entries = {e.name for e in raw_cand.iterdir()}
                    if f"index{ext}" in index_entries:
                        return ("resolved", str(index_cand))
                    for name in index_entries:
                        if name.lower() == f"index{ext}".lower():
                            return ("case_mismatch", name)
                except OSError:
                    return ("resolved", str(index_cand))
                return ("case_mismatch", f"index{ext}")

        # Directory with package.json "main" or "module" field
        pkg_json = raw_cand / "package.json"
        if pkg_json.is_file():
            try:
                import json
                doc = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                main_field = doc.get("module") or doc.get("main")
                if main_field and isinstance(main_field, str):
                    main_cand = (raw_cand / main_field).resolve()
                    if not _is_within_root(main_cand, root_resolved):
                        return ("path_traversal", None)
                    if main_cand.is_file():
                        return ("resolved", str(main_cand))
            except Exception:
                pass

    # D) TypeScript ESM rewrite: import './foo.js' where file on disk is './foo.ts'
    for orig_ext, rewrites in _TS_ESM_REWRITES.items():
        if import_spec.endswith(orig_ext):
            stem = import_spec[:-len(orig_ext)]
            for target_ext in rewrites:
                rewritten_cand = importer_dir / f"{stem}{target_ext}"
                if rewritten_cand.is_file():
                    if not _is_within_root(rewritten_cand, root_resolved):
                        return ("path_traversal", None)
                    case_ok, actual_name = _check_exact_casing(importer_dir, stem, rewritten_cand.name)
                    if case_ok:
                        return ("resolved", str(rewritten_cand))
                    return ("case_mismatch", actual_name)

    # E) Distinguish missing asset/style from missing code module
    is_asset = any(import_spec.endswith(ext) for ext in _ASSET_EXTENSIONS)
    return ("missing_asset" if is_asset else "missing_module", None)


# ---------------------------------------------------------------------------
# Public Rule Execution
# ---------------------------------------------------------------------------


def analyze_frontend_diagnostics(root: Path) -> list[Finding]:
    """Run frontend static diagnostics (FE001) across the scanned project.

    Args:
        root: Resolved absolute path to project root.

    Returns:
        List of Finding instances. Never raises; errors are caught gracefully.
    """
    findings: list[Finding] = []
    seen_ids: set[str] = set()

    # Discover frontend source directories (multi-root monorepo or standard layout)
    mono = discover_monorepo(root)
    importers: list[Path] = []
    if mono.frontend_roots:
        for fe_root in mono.frontend_roots:
            importers.extend(_iter_frontend_files(fe_root))
    else:
        frontend_root = root / "frontend" / "src"
        if not frontend_root.exists():
            frontend_root = root / "frontend"
        if not frontend_root.exists():
            frontend_root = root
        importers = _iter_frontend_files(frontend_root)

    # De-duplicate importers
    importers = list(dict.fromkeys(importers))

    for importer in importers:
        try:
            content = importer.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        relative_imports = _extract_relative_imports(content)

        for import_spec, lineno, source_snippet in relative_imports:
            if import_spec.startswith("."):
                status, detail = _resolve_relative_import(importer, import_spec, root)
            else:
                resolver = get_resolver(importer, root)
                res = resolver.resolve_specifier(import_spec, importer)
                if res.status == "resolved" and res.target_path:
                    status, detail = "resolved", str(res.target_path)
                elif res.status == "unresolved_alias":
                    status, detail = "unresolved_alias", res.alias_matched
                else:
                    # External package or not a path alias; skip
                    continue

            if status == "resolved":
                continue  # All good!

            # Stable finding ID based on importer file, line, and import specifier
            fid = hashlib.sha1(
                f"FE001:{_normalise_file(str(importer))}:{lineno}:{import_spec}".encode()
            ).hexdigest()[:12]

            if fid in seen_ids:
                continue
            seen_ids.add(fid)

            # Build finding based on resolution failure type
            if status == "unresolved_alias":
                title = f"Unresolved path alias import '{import_spec}'"
                severity = "high"
                confidence = 0.90
                alias_pattern = detail or import_spec
                message = (
                    f"The import '{import_spec}' in {importer.name} (line {lineno}) matches path alias "
                    f"'{alias_pattern}' configured in tsconfig.json, but the target file could not be found on disk."
                )
                recommendation = (
                    f"Ensure the target file exists for alias '{alias_pattern}', or update your tsconfig.json 'paths' configuration."
                )
                issue_type = "unresolved_alias"

            elif status == "path_traversal":
                title = f"Relative import '{import_spec}' traverses outside project"
                severity = "high"
                confidence = 0.95
                message = (
                    f"The relative import '{import_spec}' in {importer.name} (line {lineno}) "
                    f"attempts to reference a file outside the project root boundary. "
                    f"This creates security risks and will fail in sandboxed or container builds."
                )
                recommendation = (
                    f"Update '{import_spec}' to point to a valid internal path within the "
                    f"repository, or import from an installed package instead."
                )
                issue_type = "path_traversal"

            elif status == "case_mismatch":
                title = f"Case-sensitive import mismatch for '{import_spec}'"
                severity = "medium"
                confidence = 0.90
                actual_name = detail or "different casing"
                message = (
                    f"The relative import '{import_spec}' in {importer.name} (line {lineno}) "
                    f"does not match the actual on-disk file casing ('{actual_name}'). "
                    f"While this may work on case-insensitive filesystems (Windows/macOS), "
                    f"it will cause module resolution failures in Linux CI and production environments."
                )
                recommendation = (
                    f"Update the import path to match the exact on-disk casing: '{actual_name}'."
                )
                issue_type = "case_mismatch"

            elif status == "missing_asset":
                title = f"Unresolved relative asset import '{import_spec}'"
                severity = "medium"
                confidence = 0.65  # lower confidence: asset may be generated at build time
                message = (
                    f"The relative import '{import_spec}' in {importer.name} (line {lineno}) "
                    f"could not be resolved on disk. If this asset or stylesheet is generated "
                    f"by a build tool or pipeline step, ensure the build process runs before static checks."
                )
                recommendation = (
                    f"Verify that the file '{import_spec}' exists relative to {importer.name}, "
                    f"or verify your asset build pipeline."
                )
                issue_type = "missing_asset"

            else:  # missing_module
                title = f"Unresolved relative import '{import_spec}'"
                severity = "high"
                confidence = 0.85
                message = (
                    f"Cannot resolve relative import '{import_spec}' from {importer.name} (line {lineno}). "
                    f"No matching source file (.ts, .tsx, .js, .jsx) or directory index was found."
                )
                recommendation = (
                    f"Check that the target file exists and that the relative path is spelled correctly: "
                    f"'{import_spec}'. If the file was moved or deleted, update or remove this import."
                )
                issue_type = "missing_module"

            evidence = [
                Evidence(
                    role="frontend",
                    file=str(importer),
                    line=lineno,
                    source=source_snippet,
                )
            ]

            findings.append(
                Finding(
                    id=fid,
                    rule_id="FE001",
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    category="Frontend Diagnostics",
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

        # -------------------------------------------------------------------
        # FE002 & FE003: Missing Named or Default Exports in Resolved Modules
        # -------------------------------------------------------------------
        detailed_imports = _extract_detailed_imports(content)
        for imp in detailed_imports:
            spec = imp["spec"]
            if spec.startswith("."):
                status, target_path_str = _resolve_relative_import(importer, spec, root)
            else:
                resolver = get_resolver(importer, root)
                res = resolver.resolve_specifier(spec, importer)
                if res.status == "resolved" and res.target_path:
                    status, target_path_str = "resolved", str(res.target_path)
                else:
                    status, target_path_str = "not_resolved", None

            if status == "resolved" and target_path_str:
                target_path = Path(target_path_str)
                ext = target_path.suffix.lower()
                if ext in _CODE_EXTENSIONS and ext != ".json" and not target_path.name.endswith(".d.ts"):
                    try:
                        t_content = target_path.read_text(encoding="utf-8", errors="replace")
                        t_exports, t_has_default, t_is_indet = _extract_module_exports(t_content)
                    except OSError:
                        continue
                    if not t_is_indet and (t_exports or t_has_default):
                        # FE002: Check named imports
                        for sym in imp["named"]:
                            if sym not in t_exports:
                                fid = hashlib.sha1(f"FE002:{_normalise_file(str(importer))}:{imp['lineno']}:{sym}".encode()).hexdigest()[:12]
                                if fid not in seen_ids:
                                    seen_ids.add(fid)
                                    findings.append(Finding(
                                        id=fid,
                                        rule_id="FE002",
                                        title=f"Missing named export '{sym}' in '{target_path.name}'",
                                        severity="high",
                                        confidence=0.92,
                                        category="Frontend Diagnostics",
                                        message=f"'{importer.name}' imports named symbol '{sym}' from '{spec}', but '{target_path.name}' does not export it.",
                                        recommendation=f"Add 'export const {sym} = ...' to '{target_path.name}', or update the import in '{importer.name}'.",
                                        evidence=[
                                            Evidence(role="frontend", file=str(importer), line=imp["lineno"], source=imp["source"]),
                                            Evidence(role="frontend", file=str(target_path), line=1, source=f"// Target module {target_path.name}"),
                                        ],
                                        details={"symbol": sym, "module": spec, "target_file": str(target_path)},
                                    ))
                        # FE003: Check default import
                        if imp["default"] and not t_has_default:
                            fid = hashlib.sha1(f"FE003:{_normalise_file(str(importer))}:{imp['lineno']}:{imp['default']}".encode()).hexdigest()[:12]
                            if fid not in seen_ids:
                                seen_ids.add(fid)
                                findings.append(Finding(
                                    id=fid,
                                    rule_id="FE003",
                                    title=f"Missing default export in '{target_path.name}'",
                                    severity="high",
                                    confidence=0.90,
                                    category="Frontend Diagnostics",
                                    message=f"'{importer.name}' imports default export '{imp['default']}' from '{spec}', but '{target_path.name}' does not define a default export.",
                                    recommendation=f"Add 'export default ...' to '{target_path.name}', or use named imports instead.",
                                    evidence=[
                                        Evidence(role="frontend", file=str(importer), line=imp["lineno"], source=imp["source"]),
                                        Evidence(role="frontend", file=str(target_path), line=1, source=f"// Target module {target_path.name}"),
                                    ],
                                    details={"default_symbol": imp["default"], "module": spec, "target_file": str(target_path)},
                                ))

        # -------------------------------------------------------------------
        # FE004: Un-interpolated Path Parameter Placeholder in API Calls
        # -------------------------------------------------------------------
        clean_src = _strip_comments(content)
        raw_lines = content.splitlines()
        for m in _UNINTERPOLATED_PARAM_RE.finditer(clean_src):
            matched_url = m.group(1)
            lineno = content.count("\n", 0, m.start()) + 1
            snippet = raw_lines[lineno - 1].strip() if 0 < lineno <= len(raw_lines) else ""
            fid = hashlib.sha1(f"FE004:{_normalise_file(str(importer))}:{lineno}:{matched_url}".encode()).hexdigest()[:12]
            if fid not in seen_ids:
                seen_ids.add(fid)
                findings.append(Finding(
                    id=fid,
                    rule_id="FE004",
                    title="Un-interpolated path parameter placeholder in frontend API call",
                    severity="medium",
                    confidence=0.92,
                    category="Frontend Diagnostics",
                    message=f"Frontend call to '{matched_url}' in {importer.name} (line {lineno}) uses literal quotes containing parameter placeholder '{matched_url}'. The parameter was not interpolated and will be sent literally.",
                    recommendation="Use backticks (template literals) with `${...}` instead of static single/double quotes.",
                    evidence=[Evidence(role="frontend", file=str(importer), line=lineno, source=snippet)],
                    details={"url": matched_url, "importer_file": str(importer)},
                ))

    return findings

