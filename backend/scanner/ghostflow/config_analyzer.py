"""Configuration static analysis rules for GhostFlow.

CFG001 — Environment Variable Declaration Drift
    Detects environment variable keys accessed in source files but absent
    from the project's .env.example file.

CFG002 — Hardcoded Localhost URL
    Detects likely hardcoded development API URLs in frontend application code.

Design constraints:
- Never print, store, or expose actual .env file values.
- Never require an actual .env file to exist.
- All file discovery respects the same exclusion-directory set used elsewhere.
- can_autofix is always False for both rules.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .models import Evidence, Finding

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

# Files that are intentionally development or configuration infrastructure:
# skip these for CFG002 (localhost URL detection in frontend).
_CFG002_SKIP_PATTERNS: tuple[str, ...] = (
    # config files
    ".config.",
    "vite.config.",
    "jest.config.",
    "playwright.config.",
    "webpack.config.",
    "rollup.config.",
    "babel.config.",
    "eslint.config.",
    "prettier.config.",
    "tailwind.config.",
    "postcss.config.",
    # docs and examples
    ".md",
    ".mdx",
    ".txt",
    ".example",
    ".sample",
    # package manifests (not application code)
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    # environment templates (intentional config)
    ".env",
    ".env.example",
    ".env.local",
    ".env.development",
    ".env.production",
)

# Parent directory names in a path that indicate non-application code for CFG002
_CFG002_SKIP_PARENT_DIRS: frozenset[str] = frozenset({
    "tests",
    "test",
    "__tests__",
    "spec",
    "fixtures",
    "mocks",
    "__mocks__",
    "e2e",
    "examples",
    "docs",
    "documentation",
    "scripts",
    "tools",
})


def _is_excluded_dir(path: Path) -> bool:
    """Return True if any part of the path is an excluded directory name."""
    return any(part in _EXCLUDED_DIRS for part in path.parts)


def _iter_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    """Yield files under root with the given suffixes, skipping excluded dirs."""
    results: list[Path] = []
    if not root.is_dir():
        return results
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in suffixes:
            if not _is_excluded_dir(path):
                results.append(path)
    return results


def _normalise_file(filepath: str) -> str:
    """Normalize file path for stable hash generation."""
    p = filepath.replace("\\", "/").strip()
    return p.split("/")[-1] if "/" in p else p


# ---------------------------------------------------------------------------
# CFG001 — env-var extraction
# ---------------------------------------------------------------------------

# Python patterns
_PY_GETENV = re.compile(r"""os\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""")
_PY_ENVIRON_GET = re.compile(r"""os\.environ\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""")
_PY_ENVIRON_SUB = re.compile(r"""os\.environ\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]""")

# JS/TS patterns
_JS_PROCESS_ENV_DOT = re.compile(r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)(?!\s*\[)""")
_JS_PROCESS_ENV_BRACKET = re.compile(r"""process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]""")
_JS_IMPORT_META_ENV = re.compile(r"""import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)""")

# Keys that are legitimately available without being declared in .env.example
# (Node.js built-ins, CI variables, etc.)
_BUILTIN_KEYS: frozenset[str] = frozenset({
    "NODE_ENV",
    "PORT",
    "HOST",
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "PWD",
    "TMPDIR",
    "TEMP",
    "TMP",
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_ENV",
    "GITHUB_TOKEN",
    "HEROKU",
    "DYNO",
    "RAILWAY_ENVIRONMENT",
    "VERCEL",
    "VERCEL_ENV",
    "VERCEL_URL",
    "AWS_EXECUTION_ENV",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "LAMBDA_TASK_ROOT",
})


def _extract_env_keys_from_python(
    root: Path,
) -> list[tuple[str, str, int, str]]:
    """Extract env-var keys from Python source files.

    Returns list of (key_name, file_path_str, line_number, source_snippet).
    """
    results: list[tuple[str, str, int, str]] = []
    for path in _iter_files(root, (".py",)):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern in (_PY_GETENV, _PY_ENVIRON_GET, _PY_ENVIRON_SUB):
                for m in pattern.finditer(line):
                    key = m.group(1)
                    if key not in _BUILTIN_KEYS:
                        results.append((key, str(path), lineno, line.strip()))
    return results


def _extract_env_keys_from_frontend(
    root: Path,
) -> list[tuple[str, str, int, str]]:
    """Extract env-var keys from JS/TS source files.

    Returns list of (key_name, file_path_str, line_number, source_snippet).
    """
    results: list[tuple[str, str, int, str]] = []
    for path in _iter_files(root, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        if _is_excluded_dir(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern in (_JS_PROCESS_ENV_DOT, _JS_PROCESS_ENV_BRACKET, _JS_IMPORT_META_ENV):
                for m in pattern.finditer(line):
                    key = m.group(1)
                    if key not in _BUILTIN_KEYS:
                        results.append((key, str(path), lineno, line.strip()))
    return results


def _parse_env_example(env_example_path: Path) -> set[str] | None:
    """Parse .env.example and return declared key names.

    Returns None if the file does not exist.
    Only key names are collected — values are never read or stored.
    """
    if not env_example_path.is_file():
        return None
    declared: set[str] = set()
    try:
        text = env_example_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Support KEY=value, KEY= , KEY (bare), export KEY=value
        if line.startswith("export "):
            line = line[len("export "):]
        key_part = line.split("=", 1)[0].strip()
        # Validate it looks like an env-var name
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_part):
            declared.add(key_part)
    return declared


def _cfg001_findings(root: Path) -> list[Finding]:
    """Generate CFG001 findings for the given project root.

    .env.example is an optional template convention. If absent, there is no
    declaration baseline to drift from, so no finding is generated by default.
    GhostFlow does not silently impose this convention on unconfigured projects.
    """
    env_example = root / ".env.example"
    declared = _parse_env_example(env_example)

    if declared is None:
        # No .env.example file — do not impose convention by default
        return []

    # Collect all env-var usages from Python backend and JS/TS frontend
    backend_root = root / "backend"
    if not backend_root.is_dir():
        backend_root = root

    frontend_root = root / "frontend" / "src"
    if not frontend_root.exists():
        frontend_root = root / "frontend"
    if not frontend_root.exists():
        frontend_root = root

    py_usages = _extract_env_keys_from_python(backend_root)
    js_usages = _extract_env_keys_from_frontend(frontend_root)
    all_usages = py_usages + js_usages

    # Build a map: key -> list of usages, deduplicating same key+file+line
    seen: set[tuple[str, str, int]] = set()
    key_usages: dict[str, list[tuple[str, str, int, str]]] = {}
    for key, fpath, lineno, snippet in all_usages:
        dedup_key = (key, fpath, lineno)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        key_usages.setdefault(key, []).append((key, fpath, lineno, snippet))

    findings: list[Finding] = []
    for key, usages in sorted(key_usages.items()):
        if key in declared:
            continue  # declared — all good

        # Determine role from file extension
        first_file = usages[0][1]
        is_frontend_key = Path(first_file).suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
        evidence_role: str = "frontend" if is_frontend_key else "backend"

        fid = hashlib.sha1(
            f"CFG001:{key}:{_normalise_file(first_file)}".encode()
        ).hexdigest()[:12]

        evidence = [
            Evidence(
                role=evidence_role,  # type: ignore[arg-type]
                file=fpath,
                line=lineno,
                source=snippet,
            )
            for _, fpath, lineno, snippet in usages[:3]  # cap at 3 evidence items
        ]

        findings.append(
            Finding(
                id=fid,
                rule_id="CFG001",
                title=f"Environment variable '{key}' not declared in .env.example",
                severity="medium",
                confidence=0.70,
                category="Configuration",
                message=(
                    f"The environment variable '{key}' is accessed in source code "
                    f"but is not listed in .env.example. Developers cloning this "
                    f"repository will not know this variable is required."
                ),
                recommendation=(
                    f"Add '{key}=<placeholder>' to .env.example so that all contributors "
                    f"and deployment platforms know this variable is required. "
                    f"Do not commit the actual value."
                ),
                evidence=evidence,
                details={
                    "key": key,
                    "usage_count": len(usages),
                    "first_file": first_file,
                    "first_line": usages[0][2],
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# CFG002 — hardcoded localhost URL detection
# ---------------------------------------------------------------------------

# Matches http://localhost:<port> and http://127.0.0.1:<port>
# We also catch bare http://localhost (no port) and with trailing path.
# Note: lines containing process.env or import.meta.env are filtered at the
# call site, so no lookbehind needed here.
_LOCALHOST_URL_RE = re.compile(
    r"""(https?://(?:localhost|127\.0\.0\.1)(?::\d{1,5})?(?:/[^\s'"`\)]*)?(?=[\s'"`\),;]|$))""",
    re.IGNORECASE,
)

# Ports that are commonly used in development — used as additional signal
_DEV_PORTS: frozenset[int] = frozenset({
    3000, 3001, 3010, 4000, 4200, 5000, 5173, 5174, 8000, 8001, 8080, 8081,
    8888, 9000, 9090, 9200,
})


def _cfg002_should_skip_file(path: Path, frontend_root: Path) -> bool:
    """Return True if the file should be skipped for CFG002."""
    name = path.name
    name_lower = name.lower()

    # Check excluded parent dirs
    try:
        rel = path.relative_to(frontend_root)
    except ValueError:
        rel = path
    rel_parts_lower = {p.lower() for p in rel.parts[:-1]}  # all but filename
    if rel_parts_lower & _CFG002_SKIP_PARENT_DIRS:
        return True

    # Check filename patterns
    for pattern in _CFG002_SKIP_PATTERNS:
        if pattern in name_lower:
            return True

    return False


def _cfg002_findings(root: Path) -> list[Finding]:
    """Generate CFG002 findings for the given project root."""
    frontend_root = root / "frontend" / "src"
    if not frontend_root.exists():
        frontend_root = root / "frontend"
    if not frontend_root.exists():
        frontend_root = root

    findings: list[Finding] = []
    seen_ids: set[str] = set()

    for path in _iter_files(frontend_root, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        if _cfg002_should_skip_file(path, frontend_root):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = text.splitlines()
        in_block_comment = False

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track multi-line block comments
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                continue
            if stripped.startswith("/*"):
                if "*/" not in stripped:
                    in_block_comment = True
                continue

            # Skip single-line comment lines
            if stripped.startswith(("//", "*", "#")):
                continue

            # Strip inline comments (excluding http:// and https://) before searching for URLs
            clean_line = re.sub(r"(?<!:)//.*$", "", line)

            stripped_clean = clean_line.strip()
            # Skip lines that directly use env vars
            if "process.env." in stripped_clean or "import.meta.env." in stripped_clean:
                continue

            # Check if this line is a multi-line continuation of an env var fallback
            is_env_continuation = False
            for prev_idx in range(lineno - 2, max(-1, lineno - 4), -1):
                prev_line = lines[prev_idx].strip()
                if not prev_line:
                    continue
                if prev_line.endswith(";"):
                    break
                if "process.env." in prev_line or "import.meta.env." in prev_line:
                    is_env_continuation = True
                    break
                if prev_line.endswith(("{", "}", ";")):
                    break
            if is_env_continuation:
                continue

            for m in _LOCALHOST_URL_RE.finditer(clean_line):
                url = m.group(1)

                # Extract port if present
                port_match = re.search(r":(\d{1,5})(?:/|$)", url)
                port = int(port_match.group(1)) if port_match else None

                # Only flag if it looks like a real hardcoded app URL (has a port or is bare localhost)
                # Relative URLs are never matched by the regex, but double-check
                if url.startswith("/"):
                    continue

                # Check if it's an ambiguous config property fallback (e.g. config.apiUrl || 'http://localhost...')
                config_context = stripped_clean
                if lineno > 1 and not lines[lineno - 2].strip().endswith(";"):
                    config_context = lines[lineno - 2].strip() + " " + stripped_clean
                is_ambiguous_config = bool(re.search(r"\b(?:config|options|settings|env|conf)\.[a-zA-Z0-9_]+\s*(?:\|\||\?\?)", config_context))

                confidence = 0.50 if is_ambiguous_config else (0.75 if (port and port in _DEV_PORTS) else 0.65)

                fid = hashlib.sha1(
                    f"CFG002:{_normalise_file(str(path))}:{lineno}:{url}".encode()
                ).hexdigest()[:12]

                if fid in seen_ids:
                    continue
                seen_ids.add(fid)

                findings.append(
                    Finding(
                        id=fid,
                        rule_id="CFG002",
                        title="Hardcoded localhost URL in frontend code",
                        severity="medium",
                        confidence=confidence,
                        category="Configuration",
                        message=(
                            f"A hardcoded development URL '{url}' was found in "
                            f"{path.name} (line {lineno}). This URL will not work "
                            f"in staging, production, or CI environments."
                        ),
                        recommendation=(
                            f"Replace '{url}' with an environment variable such as "
                            f"'import.meta.env.VITE_API_BASE_URL' or 'process.env.REACT_APP_API_URL'. "
                            f"Set the appropriate value per environment in .env files."
                        ),
                        evidence=[
                            Evidence(
                                role="frontend",
                                file=str(path),
                                line=lineno,
                                source=stripped,
                            )
                        ],
                        details={
                            "url": url,
                            "port": port,
                            "is_common_dev_port": port in _DEV_PORTS if port else False,
                            **({"uncertainty": "URL used as fallback for configuration property"} if is_ambiguous_config else {}),
                        },
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# CFG003 — Incompatible CORS Configuration
# ---------------------------------------------------------------------------


def _cfg003_findings(root: Path) -> list[Finding]:
    """Detect incompatible CORS configuration: allow_origins=['*'] with allow_credentials=True."""
    findings: list[Finding] = []
    py_files = _iter_files(root, (".py",))
    import ast

    for f in py_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(f))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue

        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                is_cors = False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "add_middleware":
                    if node.args and isinstance(node.args[0], ast.Name) and "CORS" in node.args[0].id:
                        is_cors = True
                elif isinstance(node.func, ast.Name) and "CORS" in node.func.id:
                    is_cors = True

                if is_cors:
                    has_creds = False
                    has_wildcard_origin = False
                    for kw in node.keywords:
                        if kw.arg == "allow_credentials" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            has_creds = True
                        elif kw.arg == "allow_origins":
                            if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == "*":
                                        has_wildcard_origin = True
                            elif isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                                has_wildcard_origin = True

                    if has_creds and has_wildcard_origin:
                        lineno = node.lineno
                        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else "add_middleware(CORSMiddleware)"
                        fid = hashlib.sha1(f"CFG003:{_normalise_file(str(f))}:{lineno}".encode()).hexdigest()[:12]
                        findings.append(Finding(
                            id=fid,
                            rule_id="CFG003",
                            title="Incompatible CORS configuration (Wildcard origin with credentials)",
                            severity="high",
                            confidence=0.96,
                            category="Configuration",
                            message="CORSMiddleware is configured with allow_origins=['*'] and allow_credentials=True. Modern browsers reject cross-origin requests with credentials when the Access-Control-Allow-Origin header is a wildcard ('*').",
                            recommendation="Specify explicit origins in allow_origins (e.g. ['http://localhost:3000']) or set allow_credentials=False.",
                            evidence=[Evidence(role="backend", file=str(f), line=lineno, source=snippet)],
                            details={"file": str(f), "lineno": lineno},
                        ))
    return findings


# ---------------------------------------------------------------------------
# CFG004 — Missing Tooling Configuration
# ---------------------------------------------------------------------------


def _cfg004_findings(root: Path) -> list[Finding]:
    """Detect missing tsconfig.json when a TypeScript project manifest is present."""
    findings: list[Finding] = []
    # Check for package.json that declares typescript
    pkg_file = root / "package.json"
    if not pkg_file.is_file():
        pkg_file = root / "frontend" / "package.json"
    if not pkg_file.is_file():
        return findings

    try:
        import json
        doc = json.loads(pkg_file.read_text(encoding="utf-8", errors="replace"))
        all_deps = set()
        for k in ("dependencies", "devDependencies", "peerDependencies"):
            if isinstance(doc.get(k), dict):
                all_deps.update(doc[k].keys())
        scripts_str = str(doc.get("scripts", {})).lower()
        has_ts = "typescript" in all_deps or "tsc" in scripts_str
    except Exception:
        has_ts = False

    if not has_ts:
        return findings

    ts_files = _iter_files(root, (".ts", ".tsx"))
    app_ts = [f for f in ts_files if not any(part in _CFG002_SKIP_PARENT_DIRS for part in f.parts)]
    if app_ts:
        has_config = (
            (root / "tsconfig.json").is_file()
            or (root / "frontend" / "tsconfig.json").is_file()
            or (root / "jsconfig.json").is_file()
            or (root / "frontend" / "jsconfig.json").is_file()
        )
        if not has_config:
            sample_file = app_ts[0]
            fid = hashlib.sha1(f"CFG004:{_normalise_file(str(root))}:tsconfig".encode()).hexdigest()[:12]
            findings.append(Finding(
                id=fid,
                rule_id="CFG004",
                title="Missing TypeScript configuration (tsconfig.json)",
                severity="low",
                confidence=0.90,
                category="Configuration",
                message="TypeScript source files (.ts/.tsx) and typescript dependencies are present in package.json, but neither tsconfig.json nor jsconfig.json was found in the project root or frontend directory.",
                recommendation="Create a tsconfig.json file to configure module resolution and compiler options.",
                evidence=[Evidence(role="frontend", file=str(sample_file), line=1, source=f"// TypeScript file {sample_file.name}")],
                details={"root": str(root), "sample_ts_file": str(sample_file)},
            ))
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_config(root: Path) -> list[Finding]:
    """Run CFG001, CFG002, CFG003, and CFG004 against the project root.

    Args:
        root: Resolved absolute path to the project directory.

    Returns:
        List of Finding objects. Never raises; errors are logged and skipped.
    """
    findings: list[Finding] = []
    try:
        findings.extend(_cfg001_findings(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"CFG001 analysis failed: {exc}", stacklevel=2)
    try:
        findings.extend(_cfg002_findings(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"CFG002 analysis failed: {exc}", stacklevel=2)
    try:
        findings.extend(_cfg003_findings(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"CFG003 analysis failed: {exc}", stacklevel=2)
    try:
        findings.extend(_cfg004_findings(root))
    except Exception as exc:  # pragma: no cover
        import warnings
        warnings.warn(f"CFG004 analysis failed: {exc}", stacklevel=2)
    return findings
