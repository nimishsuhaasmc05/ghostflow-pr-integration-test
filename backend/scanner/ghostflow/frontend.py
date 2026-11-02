from __future__ import annotations
import re
from pathlib import Path
from .models import ApiCall, SchemaField, SchemaModel

# Regex patterns for fetch and axios calls
FETCH_CALL_RE = re.compile(
    r"fetch(?:<([^>]+)>)?\s*\(\s*(['\"`])([^'\"`]+)\2(?:\s*,\s*(\{[\s\S]*?\}))?\s*\)",
    re.MULTILINE
)
AXIOS_CALL_RE = re.compile(
    r"axios\.(get|post|put|patch|delete)(?:<([^>]+)>)?\s*\(\s*(['\"`])([^'\"`]+)\3(?:\s*,\s*([^,\)]+))?",
    re.IGNORECASE | re.MULTILINE
)

METHOD_RE = re.compile(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", re.IGNORECASE)
BODY_RE = re.compile(r"\bbody\s*:\s*(?:JSON\.stringify\s*\(\s*)?([A-Za-z0-9_$]+)(?:\s+as\s+([A-Za-z0-9_$]+))?", re.MULTILINE)
DATA_RE = re.compile(r"\bdata\s*:\s*([A-Za-z0-9_$]+)(?:\s+as\s+([A-Za-z0-9_$]+))?", re.MULTILINE)
URL_PROP_RE = re.compile(r"\burl\s*:\s*(['\"`][^'\"`]+['\"`]|[A-Za-z0-9_$]+)")
TEMPLATE_PARAM_RE = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}")

# Type extraction patterns
INTERFACE_START_RE = re.compile(r"(?:export\s+)?interface\s+([A-Za-z0-9_$]+)(?:\s+extends\s+[^{]+)?\s*\{")
TYPE_START_RE = re.compile(r"(?:export\s+)?type\s+([A-Za-z0-9_$]+)\s*=\s*\{")

# Function signature and typing
FUNC_SIG_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)?\s*\(([^)]*)\)(?:\s*:\s*(?:Promise<([^>]+)>|([^\{]+)))?",
    re.MULTILINE
)
ARROW_FUNC_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)(?:\s*:\s*(?:Promise<([^>]+)>|([^=]+)))?\s*=>",
    re.MULTILINE
)
PROP_ARROW_RE = re.compile(
    r"([A-Za-z0-9_$]+)\s*:\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z0-9_$]+))\s*(?:\s*:\s*(?:Promise<([^>]+)>|([^=]+)))?\s*=>",
    re.MULTILINE
)
OBJ_METHOD_RE = re.compile(
    r"(?:(?:public|private|protected|static)\s+)*(?:async\s+)?([A-Za-z0-9_$]+)\s*\(([^)]*)\)(?:\s*:\s*(?:Promise<([^>]+)>|([^\{]+)))?\s*\{",
    re.MULTILINE
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

EXCLUDED_FRONTEND_PARTS: frozenset[str] = frozenset({
    ".git", "node_modules", ".venv", "venv", "dist", "build",
    "static", ".next", "out", "coverage", "__pycache__", ".turbo"
})

# Blacklist of objects whose .get / .post methods should never be treated as API clients
BLACKLISTED_OBJECTS = {
    "map", "set", "searchparams", "params", "urlparams", "formdata", "headers",
    "cookies", "cache", "store", "state", "ref", "res", "response", "req",
    "console", "document", "window", "math", "json", "object", "array",
    "promise", "history", "location", "event", "form", "localstorage",
    "sessionstorage", "query", "url", "path", "dict", "props", "lodash", "_",
}

BLACKLISTED_SUFFIXES = (
    "map", "set", "params", "formdata", "headers", "cache", "store",
    "state", "ref", "response", "req", "event", "form", "list", "array",
    "cookie", "cookies"
)

BLACKLISTED_PREFIXES = (
    "cache", "store", "map", "set", "form", "cookie"
)

CLIENT_METHOD_CALL_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete)(?:<([^>]+)>)?\s*\(",
    re.IGNORECASE
)

STANDARD_WRAPPER_NAMES = {
    "fetch", "apirequest", "apicall", "fetchapi", "request",
    "client", "apiclient", "axios", "http", "api"
}


def _is_api_client_name(name: str, local_clients: set[str] | None = None) -> bool:
    if local_clients and name in local_clients:
        return True
    lower = name.lower()
    if lower in BLACKLISTED_OBJECTS:
        return False
    if any(lower.endswith(suffix) for suffix in BLACKLISTED_SUFFIXES):
        return False
    if any(lower.startswith(prefix) for prefix in BLACKLISTED_PREFIXES):
        return False
    if lower in {"axios", "apiclient", "client", "api", "http", "httpclient", "request", "service", "restclient", "caller"}:
        return True
    if lower.endswith(("client", "service", "api", "http")):
        return True
    return False


def _extract_imported_api_clients_and_wrappers(content: str) -> tuple[set[str], set[str]]:
    """Extract locally imported API clients and wrapper function names based on import paths."""
    imported_clients: set[str] = set()
    imported_wrappers: set[str] = set()
    clean = _strip_comments(content)

    import_re = re.compile(
        r"import\s+(?:(?:\*\s+as\s+([A-Za-z0-9_$]+))|([A-Za-z0-9_$]+)|(?:\{([^}]+)\}))\s+from\s+['\"]([^'\"]+)['\"]",
        re.MULTILINE
    )

    for m in import_re.finditer(clean):
        ns_import = m.group(1)
        default_import = m.group(2)
        named_imports = m.group(3)
        source_module = m.group(4).lower()

        is_api_module = any(token in source_module for token in ("api", "client", "service", "http", "request", "fetch"))
        if not is_api_module:
            continue

        if ns_import:
            imported_clients.add(ns_import)
        if default_import:
            if any(t in default_import.lower() for t in ("client", "api", "http", "service")):
                imported_clients.add(default_import)
            else:
                imported_wrappers.add(default_import)
        if named_imports:
            for item in named_imports.split(","):
                token = item.strip()
                if not token:
                    continue
                if " as " in token:
                    token = token.split(" as ")[1].strip()
                t_lower = token.lower()
                if any(t_lower.endswith(s) for s in ("client", "service", "api", "http")) or t_lower in ("client", "api", "http"):
                    imported_clients.add(token)
                else:
                    imported_wrappers.add(token)

    return (imported_clients, imported_wrappers)


def _extract_client_instantiations(content: str) -> set[str]:
    """Find variable names assigned from client factories (axios.create, new ApiClient, etc.)."""
    local_clients: set[str] = set()
    clean = _strip_comments(content)
    pattern = re.compile(
        r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:axios\.create|new\s+[A-Za-z0-9_$]*(?:Client|Api|Service|Http)|createClient|createApi|createHttpClient)",
        re.MULTILINE
    )
    for m in pattern.finditer(clean):
        local_clients.add(m.group(1))
    return local_clients


def _strip_comments(source: str) -> str:
    """Replace comments with whitespace to preserve exact character and line counts, respecting quotes."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        # String literal guard: do not strip // or /* inside quotes
        if source[i] in ("'", '"', '`'):
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


def _find_matching_paren(content: str, open_paren_idx: int) -> int:
    """Find index of matching closing parenthesis, respecting string literals."""
    depth = 0
    in_single = False
    in_double = False
    in_backtick = False
    escape = False

    for idx in range(open_paren_idx, len(content)):
        char = content[idx]

        if escape:
            escape = False
            continue

        if char == "\\":
            escape = True
            continue

        if char == "'" and not in_double and not in_backtick:
            in_single = not in_single
            continue
        if char == '"' and not in_single and not in_backtick:
            in_double = not in_double
            continue
        if char == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            continue

        if not in_single and not in_double and not in_backtick:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return idx

    return -1


def _find_concise_body_end(content: str, start_idx: int) -> int:
    """Find end of a concise body arrow function (ends at comma, semicolon, newline, or unclosed brace)."""
    depth_paren = 0
    depth_bracket = 0
    depth_brace = 0
    in_single = False
    in_double = False
    in_backtick = False
    escape = False

    for idx in range(start_idx, len(content)):
        char = content[idx]
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == "'" and not in_double and not in_backtick:
            in_single = not in_single
            continue
        if char == '"' and not in_single and not in_backtick:
            in_double = not in_double
            continue
        if char == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            continue
        if not in_single and not in_double and not in_backtick:
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]":
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}":
                if depth_brace == 0:
                    return idx
                depth_brace -= 1
            elif char in (",", ";") and depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
                return idx
    return len(content)


def _split_arguments(arg_str: str) -> list[str]:
    """Split comma-separated function arguments respecting quotes, braces, and brackets."""
    args: list[str] = []
    current: list[str] = []
    depth_paren = 0
    depth_brace = 0
    depth_bracket = 0
    in_single = False
    in_double = False
    in_backtick = False
    escape = False

    for char in arg_str:
        if escape:
            escape = False
            current.append(char)
            continue
        if char == "\\":
            escape = True
            current.append(char)
            continue
        if char == "'" and not in_double and not in_backtick:
            in_single = not in_single
            current.append(char)
            continue
        if char == '"' and not in_single and not in_backtick:
            in_double = not in_double
            current.append(char)
            continue
        if char == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            current.append(char)
            continue

        if not in_single and not in_double and not in_backtick:
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}":
                depth_brace -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]":
                depth_bracket -= 1
            elif char == "," and depth_paren == 0 and depth_brace == 0 and depth_bracket == 0:
                args.append("".join(current).strip())
                current = []
                continue

        current.append(char)

    if current:
        token = "".join(current).strip()
        if token:
            args.append(token)

    return args


def _extract_constants(content: str) -> dict[str, str]:
    """Extract string constants and base URLs defined in the file, resolving concatenations and templates."""
    constants: dict[str, str] = {}
    clean = _strip_comments(content)

    # 1. Simple string literals: const BASE = '/api' or const HOST = "http://localhost:8000"
    for m in re.finditer(r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(['\"`])([^'\"`]*)\2", clean):
        val = m.group(3)
        # Backtick template strings containing ${...} are not simple literals and must be resolved in step 2
        if m.group(2) == "`" and "${" in val:
            continue
        constants[m.group(1)] = val

    # 2. Iteratively resolve constants defined via concatenation or other constants
    for _ in range(3):
        for m in re.finditer(r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*([^;\n]+)", clean):
            name = m.group(1)
            raw_val = m.group(2).strip()
            if name in constants:
                continue
            if "+" in raw_val:
                parts = [p.strip() for p in raw_val.split("+")]
                resolved_parts: list[str] = []
                ok = True
                for p in parts:
                    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
                        resolved_parts.append(p[1:-1])
                    elif p in constants:
                        resolved_parts.append(constants[p])
                    else:
                        ok = False
                        break
                if ok:
                    constants[name] = "".join(resolved_parts)
            elif raw_val.startswith("`") and raw_val.endswith("`"):
                inner = raw_val[1:-1]
                def repl(match: re.Match) -> str:
                    v = match.group(1)
                    return constants.get(v, f"${{{v}}}")
                resolved = TEMPLATE_PARAM_RE.sub(repl, inner)
                if not TEMPLATE_PARAM_RE.search(resolved):
                    constants[name] = resolved

    return constants


def _normalise_path(raw: str) -> str:
    path = TEMPLATE_PARAM_RE.sub(lambda m: "{" + m.group(1) + "}", raw)
    if "?" in path:
        path = path.split("?")[0]
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def _resolve_url_expression(expr: str, constants: dict[str, str]) -> tuple[str, list[str], bool]:
    """Resolve a URL argument expression (literal, template string, constant, or concatenation)."""
    expr = expr.strip()
    if not expr:
        return ("<unresolved>", [], True)

    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1].strip()

    # 1. Simple quoted string: "/users" or '/users'
    if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
        raw = expr[1:-1]
        raw_clean = re.sub(r"^https?://[^/]+", "", raw)
        path = _normalise_path(raw_clean)
        path_only = raw_clean.split("?")[0] if "?" in raw_clean else raw_clean
        params = TEMPLATE_PARAM_RE.findall(path_only)
        return (path, params, False)

    # 2. Template string: `/users/${userId}` or `${API_BASE}/users/${id}`
    if expr.startswith("`") and expr.endswith("`"):
        inner = expr[1:-1]

        # Strip known base env/config prefixes if at start, e.g. `${process.env.REACT_APP_API_URL}`
        inner = re.sub(r"^\$\{(?:process\.env|import\.meta\.env)\.[A-Za-z0-9_$]+\}", "", inner)

        # Detect complex expressions inside ${...} (e.g. ${this.baseUrl}, ${options.url}, ${fn()})
        for expr_match in re.finditer(r"\$\{\s*([^}]+)\s*\}", inner):
            expr_body = expr_match.group(1).strip()
            if "." in expr_body or "(" in expr_body or "[" in expr_body:
                return ("<unresolved>", [], True)

        is_dynamic = False

        def replace_var(m: re.Match) -> str:
            nonlocal is_dynamic
            var_name = m.group(1)
            if var_name in constants:
                const_val = constants[var_name]
                const_val = re.sub(r"^https?://[^/]+", "", const_val)
                return const_val
            # If variable is a known base URL name without constant definition, strip if at start
            if var_name.upper() in {"API_BASE", "BASE_URL", "API_URL", "HOST", "SERVER_URL", "BACKEND_URL"}:
                return ""
            # Check if it's a simple identifier
            if re.match(r"^[A-Za-z_$][\w$]*$", var_name):
                return f"${{{var_name}}}"
            is_dynamic = True
            return f"${{{var_name}}}"

        resolved_inner = TEMPLATE_PARAM_RE.sub(replace_var, inner)
        if is_dynamic:
            return ("<unresolved>", [], True)

        resolved_clean = re.sub(r"^https?://[^/]+", "", resolved_inner)
        path_only = resolved_clean.split("?")[0] if "?" in resolved_clean else resolved_clean
        params = TEMPLATE_PARAM_RE.findall(path_only)
        path = _normalise_path(resolved_clean)

        # If the resolved path has no static segments (only variable placeholders like /{url}), it is a generic wrapper call
        static_segments = [s for s in path.split("/") if s and not (s.startswith("{") and s.endswith("}"))]
        if not static_segments:
            return ("<unresolved>", [], True)

        return (path, params, False)

    # 3. Known constant identifier: e.g. USERS_URL
    if expr in constants:
        val = constants[expr]
        if val.startswith("`") and val.endswith("`"):
            return _resolve_url_expression(val, constants)
        if "${" in val:
            return _resolve_url_expression(f"`{val}`", constants)
        val_clean = re.sub(r"^https?://[^/]+", "", val)
        path = _normalise_path(val_clean)
        params = TEMPLATE_PARAM_RE.findall(val_clean)
        return (path, params, False)

    # 4. String concatenation with +: e.g. BASE_URL + "/users" or "/users/" + id or BASE + '/' + id
    if "+" in expr:
        parts = [p.strip() for p in expr.split("+")]
        combined_parts: list[str] = []
        params: list[str] = []
        is_dynamic = False

        for p in parts:
            if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
                combined_parts.append(p[1:-1])
            elif p.startswith("`") and p.endswith("`"):
                sub_path, sub_params, sub_dyn = _resolve_url_expression(p, constants)
                if sub_dyn:
                    is_dynamic = True
                combined_parts.append(sub_path)
                params.extend(sub_params)
            elif p in constants:
                const_val = constants[p]
                const_val = re.sub(r"^https?://[^/]+", "", const_val)
                combined_parts.append(const_val)
            elif re.match(r"^[A-Za-z_$][\w$]*$", p):
                combined_parts.append(f"{{{p}}}")
                params.append(p)
            else:
                is_dynamic = True

        if is_dynamic:
            return ("<unresolved>", [], True)

        full_raw = "".join(combined_parts)
        full_clean = re.sub(r"^https?://[^/]+", "", full_raw)
        norm_path = _normalise_path(full_clean)
        return (norm_path, params, False)

    # Unresolved dynamic expression (function call, object property, unknown variable)
    return ("<unresolved>", [], True)


def _find_matching_brace(content: str, open_idx: int) -> int:
    """Find index of matching closing brace for the opening brace at open_idx."""
    depth = 0
    for idx in range(open_idx, len(content)):
        char = content[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def extract_frontend_models(root: Path) -> dict[str, SchemaModel]:
    """Extract TypeScript interfaces and type object definitions across the frontend codebase."""
    models: dict[str, SchemaModel] = {}
    if not root.exists():
        return models

    for file in sorted(root.rglob("*")):
        if not file.is_file() or file.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        if any(part in EXCLUDED_FRONTEND_PARTS for part in file.parts):
            continue
        try:
            content = file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        clean = _strip_comments(content)
        lines = content.splitlines()

        # Find interfaces and types
        starts: list[tuple[str, int, int]] = []
        for m in INTERFACE_START_RE.finditer(clean):
            starts.append((m.group(1), m.start(), m.end() - 1))
        for m in TYPE_START_RE.finditer(clean):
            starts.append((m.group(1), m.start(), m.end() - 1))

        for name, match_start, open_brace_idx in starts:
            close_brace_idx = _find_matching_brace(clean, open_brace_idx)
            if close_brace_idx == -1:
                continue

            body = content[open_brace_idx + 1:close_brace_idx]
            model_line = content.count("\n", 0, match_start) + 1
            model_source = lines[model_line - 1].strip()[:240] if 0 < model_line <= len(lines) else ""

            fields: dict[str, SchemaField] = {}
            for field_match in re.finditer(r"([A-Za-z0-9_$]+)(\?)?\s*:\s*([^;,\n}]+)", body):
                field_name = field_match.group(1)
                is_optional = bool(field_match.group(2))
                raw_type = field_match.group(3).strip()

                if "undefined" in raw_type.split("|") or "null" in raw_type.split("|"):
                    is_optional = True

                field_offset = open_brace_idx + 1 + field_match.start()
                field_line = content.count("\n", 0, field_offset) + 1
                field_source = lines[field_line - 1].strip()[:240] if 0 < field_line <= len(lines) else ""

                nested_candidate = re.sub(r"^(?:Array<|ReadonlyArray<)(.*)>$", r"\1", raw_type).strip()
                if nested_candidate.endswith("[]"):
                    nested_candidate = nested_candidate[:-2].strip()

                fields[field_name] = SchemaField(
                    name=field_name,
                    type_name=raw_type,
                    is_required=not is_optional,
                    nested_model=nested_candidate if (nested_candidate and nested_candidate not in {"string", "number", "boolean", "any"}) else None,
                    file=file.as_posix(),
                    line=field_line,
                    source=field_source,
                )

            models[name] = SchemaModel(
                name=name,
                file=file.as_posix(),
                line=model_line,
                source=model_source,
                fields=fields,
            )

    # Resolve nested fields
    for model in models.values():
        for field in model.fields.values():
            if field.nested_model and field.nested_model in models:
                field.nested_fields = models[field.nested_model].fields

    return models


def _extract_scopes(content: str) -> list[dict]:
    """Extract function blocks and service methods (including concise arrow properties) to associate types."""
    scopes: list[dict] = []
    clean = _strip_comments(content)

    candidates: list[tuple[int, str, str | None, bool]] = []
    for m in FUNC_SIG_RE.finditer(clean):
        candidates.append((m.start(), m.group(2), m.group(3) or m.group(4), False))
    for m in ARROW_FUNC_RE.finditer(clean):
        candidates.append((m.start(), m.group(2), m.group(3) or m.group(4), True))
    for m in PROP_ARROW_RE.finditer(clean):
        params_token = m.group(2) or m.group(3)
        candidates.append((m.start(), params_token, m.group(4) or m.group(5), True))
    for m in OBJ_METHOD_RE.finditer(clean):
        candidates.append((m.start(), m.group(2), m.group(3) or m.group(4), False))

    for start_idx, raw_params, ret_type, is_arrow in candidates:
        open_brace = -1
        end_pos = -1

        if is_arrow:
            arrow_pos = clean.find("=>", start_idx)
            if arrow_pos != -1:
                after_arrow = clean[arrow_pos + 2:].lstrip()
                if after_arrow and after_arrow[0] == "{":
                    open_brace = clean.find("{", arrow_pos)
                    end_pos = _find_matching_brace(clean, open_brace)
                else:
                    end_pos = _find_concise_body_end(clean, arrow_pos + 2)
        else:
            open_brace = clean.find("{", start_idx)
            if open_brace != -1:
                end_pos = _find_matching_brace(clean, open_brace)

        if end_pos == -1:
            continue

        param_types: dict[str, str] = {}
        if raw_params:
            for p in raw_params.split(","):
                parts = p.split(":")
                if len(parts) == 2:
                    pname = parts[0].strip().replace("?", "")
                    ptype = parts[1].strip().split("=")[0].strip()
                    param_types[pname] = ptype

        clean_ret = (ret_type or "").strip()
        if clean_ret.startswith("Promise<") and clean_ret.endswith(">"):
            clean_ret = clean_ret[8:-1].strip()

        scopes.append({
            "start": start_idx,
            "end": end_pos,
            "params": param_types,
            "return_type": clean_ret or None,
            "body": content[start_idx:end_pos],
        })

    return scopes


def _get_param_types(params: list[str], scope: dict | None) -> dict[str, str]:
    param_types: dict[str, str] = {}
    if scope and "params" in scope:
        for p in params:
            if p in scope["params"]:
                param_types[p] = scope["params"][p]
    return param_types


def _get_response_type(content: str, close_paren_offset: int, scope: dict | None) -> str | None:
    snippet = content[close_paren_offset:close_paren_offset + 400]
    res_match = re.search(
        r"\.(?:json\s*\(\s*\)|data)\s+as\s+(?:Promise<([^>]+)>|([A-Za-z0-9_$]+))",
        snippet
    )
    if res_match:
        return res_match.group(1) or res_match.group(2)
    if scope and scope.get("return_type"):
        return scope["return_type"]
    return None


def extract_frontend_calls(root: Path, models: dict[str, SchemaModel] | None = None) -> list[ApiCall]:
    """Extract frontend API calls (fetch, axios, apiClient, wrapper functions) with request and response types."""
    if models is None:
        models = extract_frontend_models(root)

    calls: list[ApiCall] = []
    if not root.exists():
        return calls

    for file in sorted(root.rglob("*")):
        if not file.is_file() or file.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        if any(part in EXCLUDED_FRONTEND_PARTS for part in file.parts):
            continue
        try:
            content = file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        lines = content.splitlines()
        scopes = _extract_scopes(content)
        constants = _extract_constants(content)

        imported_clients, imported_wrappers = _extract_imported_api_clients_and_wrappers(content)
        instantiated_clients = _extract_client_instantiations(content)
        local_clients = imported_clients.union(instantiated_clients)

        all_wrapper_names = STANDARD_WRAPPER_NAMES.union({w.lower() for w in imported_wrappers})
        wrapper_pattern = (
            r"\b(?:window\.)?("
            + "|".join(re.escape(w) for w in sorted(all_wrapper_names, key=len, reverse=True))
            + r")(?:<([^>]+)>)?\s*\("
        )
        wrapper_re = re.compile(wrapper_pattern, re.IGNORECASE)

        def get_enclosing_scope(offset: int) -> dict | None:
            for s in scopes:
                if s["start"] <= offset <= s["end"]:
                    return s
            return None

        # 1. Wrapper calls: fetch(...), apiClient(...), request(...), customWrapper(...)
        for match in wrapper_re.finditer(content):
            call_offset = match.start()
            wrapper_name = match.group(1)
            generic_type = match.group(2)

            open_paren = content.find("(", match.end() - 1)
            if open_paren == -1:
                continue
            close_paren = _find_matching_paren(content, open_paren)
            if close_paren == -1:
                continue

            args_str = content[open_paren + 1:close_paren]
            args = _split_arguments(args_str)
            if not args:
                continue

            line = content.count("\n", 0, call_offset) + 1
            source = lines[line - 1].strip()[:240] if 0 < line <= len(lines) else content[call_offset:call_offset + 100]

            # Check for config object format: e.g. client({ url: '/api/users', method: 'POST', data: ... })
            if args[0].startswith("{"):
                cfg_obj = args[0]
                url_m = URL_PROP_RE.search(cfg_obj)
                if not url_m:
                    continue
                clean_path, params, is_dyn = _resolve_url_expression(url_m.group(1), constants)
                method_m = METHOD_RE.search(cfg_obj)
                method = method_m.group(1).upper() if method_m else "GET"

                if is_dyn or clean_path == "<unresolved>":
                    calls.append(ApiCall(
                        method=method,
                        path="<unresolved>",
                        file=file.as_posix(),
                        line=line,
                        source=source,
                        is_dynamic=True,
                    ))
                    continue

                if not clean_path.startswith("/"):
                    continue

                body_m = BODY_RE.search(cfg_obj) or DATA_RE.search(cfg_obj)
                payload_var = body_m.group(1) if body_m else None
                explicit_as = body_m.group(2) if body_m else None

                scope = get_enclosing_scope(call_offset)
                param_types = _get_param_types(params, scope)

                request_type_name = explicit_as or (scope["params"].get(payload_var) if scope and payload_var else None)
                response_type_name = generic_type or _get_response_type(content, close_paren, scope)
                has_auth = any(k in cfg_obj.lower() or k in source.lower() for k in ("auth", "token", "bearer", "authorization", "credential"))

                calls.append(ApiCall(
                    method=method,
                    path=clean_path,
                    file=file.as_posix(),
                    line=line,
                    source=source,
                    raw_path_params=params,
                    path_param_types=param_types,
                    request_type=request_type_name,
                    response_type=response_type_name,
                    request_schema=models.get(request_type_name) if request_type_name else None,
                    response_schema=models.get(response_type_name) if response_type_name else None,
                    is_dynamic=False,
                    has_auth_header=has_auth,
                ))
                continue

            # Standard wrapper call: fetch(url, options) or request(url, options)
            clean_path, params, is_dyn = _resolve_url_expression(args[0], constants)
            options_block = args[1] if len(args) > 1 else ""
            method_match = METHOD_RE.search(options_block)
            method = method_match.group(1).upper() if method_match else "GET"

            if is_dyn or clean_path == "<unresolved>":
                calls.append(ApiCall(
                    method=method,
                    path="<unresolved>",
                    file=file.as_posix(),
                    line=line,
                    source=source,
                    is_dynamic=True,
                ))
                continue

            if not clean_path.startswith("/"):
                continue

            scope = get_enclosing_scope(call_offset)
            param_types = _get_param_types(params, scope)

            request_type_name = None
            body_match = BODY_RE.search(options_block) or DATA_RE.search(options_block)
            if body_match:
                payload_var = body_match.group(1)
                explicit_as = body_match.group(2)
                if explicit_as:
                    request_type_name = explicit_as
                elif scope and payload_var in scope["params"]:
                    request_type_name = scope["params"][payload_var]

            response_type_name = generic_type or _get_response_type(content, close_paren, scope)
            has_auth = any(k in options_block.lower() or k in source.lower() for k in ("auth", "token", "bearer", "authorization", "credential"))

            calls.append(ApiCall(
                method=method,
                path=clean_path,
                file=file.as_posix(),
                line=line,
                source=source,
                raw_path_params=params,
                path_param_types=param_types,
                request_type=request_type_name,
                response_type=response_type_name,
                request_schema=models.get(request_type_name) if request_type_name else None,
                response_schema=models.get(response_type_name) if response_type_name else None,
                is_dynamic=False,
                has_auth_header=has_auth,
            ))

        # 2. Client method calls: client.(get|post|put|patch|delete)<generic>(url, payload, options)
        for match in CLIENT_METHOD_CALL_RE.finditer(content):
            call_offset = match.start()
            client_name = match.group(1)
            method = match.group(2).upper()
            generic_type = match.group(3)

            if not _is_api_client_name(client_name, local_clients):
                continue

            open_paren = content.find("(", match.end() - 1)
            if open_paren == -1:
                continue
            close_paren = _find_matching_paren(content, open_paren)
            if close_paren == -1:
                continue

            args_str = content[open_paren + 1:close_paren]
            args = _split_arguments(args_str)
            if not args:
                continue

            line = content.count("\n", 0, call_offset) + 1
            source = lines[line - 1].strip()[:240] if 0 < line <= len(lines) else content[call_offset:call_offset + 100]

            clean_path, params, is_dyn = _resolve_url_expression(args[0], constants)
            if is_dyn or clean_path == "<unresolved>":
                calls.append(ApiCall(
                    method=method,
                    path="<unresolved>",
                    file=file.as_posix(),
                    line=line,
                    source=source,
                    is_dynamic=True,
                ))
                continue

            if not clean_path.startswith("/"):
                continue

            scope = get_enclosing_scope(call_offset)
            param_types = _get_param_types(params, scope)

            response_type_name: str | None = None
            request_type_name: str | None = None

            # Generic type arguments: client.post<Response, Request>
            if generic_type:
                g_parts = [g.strip() for g in generic_type.split(",")]
                if len(g_parts) >= 1 and g_parts[0] not in ("any", "unknown"):
                    response_type_name = g_parts[0]
                if len(g_parts) >= 3 and g_parts[2] not in ("any", "unknown"):
                    request_type_name = g_parts[2]
                elif len(g_parts) >= 2 and method in {"POST", "PUT", "PATCH"} and g_parts[1] not in ("any", "unknown"):
                    request_type_name = g_parts[1]

            # Payload argument inspection: client.post('/path', payload as RequestType)
            if len(args) >= 2 and method in {"POST", "PUT", "PATCH"}:
                payload_arg = args[1].strip()
                if not request_type_name:
                    as_match = re.search(r"\bas\s+([A-Za-z0-9_$]+)", payload_arg)
                    if as_match:
                        request_type_name = as_match.group(1)
                    elif scope and payload_arg in scope["params"]:
                        request_type_name = scope["params"][payload_arg]

            if not response_type_name:
                response_type_name = _get_response_type(content, close_paren, scope)

            call_text = content[call_offset:close_paren].lower()
            has_auth = any(k in call_text for k in ("auth", "token", "bearer", "authorization", "credential"))

            calls.append(ApiCall(
                method=method,
                path=clean_path,
                file=file.as_posix(),
                line=line,
                source=source,
                raw_path_params=params,
                path_param_types=param_types,
                request_type=request_type_name,
                response_type=response_type_name,
                request_schema=models.get(request_type_name) if request_type_name else None,
                response_schema=models.get(response_type_name) if response_type_name else None,
                is_dynamic=False,
                has_auth_header=has_auth,
            ))

    # Deduplicate exact duplicate call declarations (same file, line, method, path)
    seen_keys: set[tuple[str, int, str, str]] = set()
    unique_calls: list[ApiCall] = []
    for c in calls:
        key = (c.file, c.line, c.method, c.path)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_calls.append(c)

    return unique_calls
