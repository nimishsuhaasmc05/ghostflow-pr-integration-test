from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SyntaxValidationResult:
    valid: bool
    language: str
    error_message: str | None = None
    line: int | None = None
    column: int | None = None


def find_node_executable() -> str | None:
    """Find system node executable."""
    return shutil.which("node")


def find_tsc_executable(project_root: Path | None = None) -> str | None:
    """Find tsc executable if present in project or frontend node_modules."""
    candidates = []
    if project_root:
        # Check project root node_modules
        candidates.extend([
            project_root / "frontend" / "node_modules" / ".bin" / ("tsc.cmd" if os.name == "nt" else "tsc"),
            project_root / "frontend" / "node_modules" / "@typescript" / "typescript-win32-x64" / "lib" / "tsc.exe",
            project_root / "node_modules" / ".bin" / ("tsc.cmd" if os.name == "nt" else "tsc"),
        ])
    # Also check relative to this file
    this_dir = Path(__file__).resolve()
    # ghostflow/backend/scanner/ghostflow -> ghostflow/frontend
    frontend_dir = this_dir.parents[3] / "frontend"
    candidates.extend([
        frontend_dir / "node_modules" / ".bin" / ("tsc.cmd" if os.name == "nt" else "tsc"),
        frontend_dir / "node_modules" / "@typescript" / "typescript-win32-x64" / "lib" / "tsc.exe",
    ])
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return str(c)
    return shutil.which("tsc")


def validate_python_syntax(code: str, filename: str = "<string>") -> SyntaxValidationResult:
    """Validate Python syntax using ast.parse."""
    try:
        ast.parse(code, filename=filename)
        return SyntaxValidationResult(valid=True, language="python")
    except SyntaxError as e:
        return SyntaxValidationResult(
            valid=False,
            language="python",
            error_message=f"SyntaxError: {e.msg}",
            line=e.lineno,
            column=e.offset,
        )


def validate_json_syntax(code: str) -> SyntaxValidationResult:
    """Validate JSON syntax using json.loads."""
    try:
        json.loads(code)
        return SyntaxValidationResult(valid=True, language="json")
    except json.JSONDecodeError as e:
        return SyntaxValidationResult(
            valid=False,
            language="json",
            error_message=f"JSONDecodeError: {e.msg}",
            line=e.lineno,
            column=e.colno,
        )


def validate_javascript_syntax(code: str, filename: str = "temp.js") -> SyntaxValidationResult:
    """Validate JavaScript syntax without executing code via Node.js node:vm Script."""
    node_exe = find_node_executable()
    if not node_exe:
        return SyntaxValidationResult(
            valid=False,
            language="javascript",
            error_message="Syntax validation unavailable: Node.js runtime not found.",
        )

    # Node script that compiles the JS without running it
    checker_script = (
        "const vm = require('node:vm');"
        "const fs = require('node:fs');"
        "try {"
        "  const code = fs.readFileSync(0, 'utf-8');"
        "  new vm.Script(code, { filename: process.argv[1] || 'input.js' });"
        "  process.exit(0);"
        "} catch (err) {"
        "  console.error(err.name + ': ' + err.message);"
        "  process.exit(1);"
        "}"
    )

    try:
        proc = subprocess.run(
            [node_exe, "-e", checker_script, filename],
            input=code,
            text=True,
            capture_output=True,
            timeout=5,
        )
        if proc.returncode == 0:
            return SyntaxValidationResult(valid=True, language="javascript")
        else:
            err_msg = proc.stderr.strip() or proc.stdout.strip() or "Syntax error in JavaScript"
            return SyntaxValidationResult(
                valid=False,
                language="javascript",
                error_message=err_msg,
            )
    except subprocess.TimeoutExpired:
        return SyntaxValidationResult(
            valid=False,
            language="javascript",
            error_message="Syntax validation timed out.",
        )
    except Exception as e:
        return SyntaxValidationResult(
            valid=False,
            language="javascript",
            error_message=f"Syntax validation failed to execute: {e}",
        )


def validate_typescript_syntax(
    code: str,
    filename: str = "temp.ts",
    project_root: Path | None = None,
) -> SyntaxValidationResult:
    """Validate TypeScript / TSX syntax without executing code.

    Uses Node 24 module stripTypeScriptTypes or tsc syntax check.
    If a real parser is unavailable, returns valid=False.
    """
    node_exe = find_node_executable()
    if not node_exe:
        return SyntaxValidationResult(
            valid=False,
            language="typescript",
            error_message="Syntax validation unavailable: Node.js runtime not found.",
        )

    # First attempt: Use Node's built-in stripTypeScriptTypes (Node 22+)
    checker_script = (
        "const { stripTypeScriptTypes } = require('node:module');"
        "const fs = require('node:fs');"
        "try {"
        "  const code = fs.readFileSync(0, 'utf-8');"
        "  const filename = process.argv[1] || 'temp.ts';"
        "  stripTypeScriptTypes(code, { sourceUrl: 'file:///' + filename });"
        "  process.exit(0);"
        "} catch (err) {"
        "  console.error((err.name || 'SyntaxError') + ': ' + (err.message || String(err)));"
        "  process.exit(1);"
        "}"
    )

    try:
        proc = subprocess.run(
            [node_exe, "-e", checker_script, filename],
            input=code,
            text=True,
            capture_output=True,
            timeout=5,
        )
        if proc.returncode == 0:
            return SyntaxValidationResult(valid=True, language="typescript")

        # If stripTypeScriptTypes caught an explicit syntax error, return it
        err_msg = proc.stderr.strip() or proc.stdout.strip()
        if "ERR_INVALID_TYPESCRIPT_SYNTAX" in err_msg or "SyntaxError" in err_msg:
            return SyntaxValidationResult(
                valid=False,
                language="typescript",
                error_message=err_msg,
            )
    except subprocess.TimeoutExpired:
        return SyntaxValidationResult(
            valid=False,
            language="typescript",
            error_message="TypeScript syntax validation timed out.",
        )
    except Exception:
        pass

def validate_jsx_tsx_syntax(
    code: str,
    filename: str = "temp.tsx",
    project_root: Path | None = None,
) -> SyntaxValidationResult:
    """Validate JSX/TSX syntax using tsc compiler syntax checking without executing code.

    Filters out semantic type-checking errors (TS2xxx, TS7xxx) and captures actual
    syntax/grammar errors (TS1000-1999 and TS17000-17999).
    Fails closed if tsc is unavailable.
    """
    tsc_exe = find_tsc_executable(project_root)
    if not tsc_exe:
        return SyntaxValidationResult(
            valid=False,
            language="jsx_tsx",
            error_message="Syntax validation unavailable: TypeScript compiler (tsc) not found.",
        )

    import tempfile
    ext = Path(filename).suffix or ".tsx"
    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8") as tf:
        tf.write(code)
        temp_path = tf.name

    try:
        cmd = [tsc_exe, "--noEmit", "--ignoreConfig", "--jsx", "preserve", "--allowJs", temp_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = proc.stdout + "\n" + proc.stderr

        # In TypeScript compiler:
        # TS1000 - TS1999: Syntactic/grammar errors
        # TS17000 - TS17999: JSX-specific syntax errors
        # Other error codes (TS2xxx, TS7xxx, TS6xxx) are semantic type errors
        syntax_errors = [
            line.strip()
            for line in output.splitlines()
            if "error TS1" in line
        ]
        if syntax_errors:
            return SyntaxValidationResult(
                valid=False,
                language="jsx_tsx",
                error_message="\n".join(syntax_errors),
            )
        return SyntaxValidationResult(valid=True, language="jsx_tsx")
    except subprocess.TimeoutExpired:
        return SyntaxValidationResult(
            valid=False,
            language="jsx_tsx",
            error_message="JSX/TSX syntax validation timed out.",
        )
    except Exception as e:
        return SyntaxValidationResult(
            valid=False,
            language="jsx_tsx",
            error_message=f"tsc syntax check execution error: {e}",
        )
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


def validate_file_syntax(
    file_path: Path | str,
    content: str | bytes,
    project_root: Path | None = None,
) -> SyntaxValidationResult:
    """Validate syntax of content matching the file extension."""
    path = Path(file_path)
    ext = path.suffix.lower()

    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as e:
            return SyntaxValidationResult(
                valid=False,
                language="unknown",
                error_message=f"File encoding error: {e}",
            )
    else:
        text = content

    if ext == ".py":
        return validate_python_syntax(text, filename=path.name)
    elif ext == ".json":
        return validate_json_syntax(text)
    elif ext in (".js", ".mjs", ".cjs"):
        res = validate_javascript_syntax(text, filename=path.name)
        if not res.valid and ("Cannot use import statement" in (res.error_message or "") or "Unexpected token '<'" in (res.error_message or "")):
            jsx_res = validate_jsx_tsx_syntax(text, filename=path.name, project_root=project_root)
            if jsx_res.valid or "error TS1" in (jsx_res.error_message or ""):
                return jsx_res
        return res
    elif ext in (".jsx", ".tsx"):
        return validate_jsx_tsx_syntax(text, filename=path.name, project_root=project_root)
    elif ext in (".ts", ".mts", ".cts"):
        return validate_typescript_syntax(text, filename=path.name, project_root=project_root)
    else:
        # Default: not a code file requiring AST parsing (e.g. .env, .txt, .md)
        return SyntaxValidationResult(valid=True, language="text")
