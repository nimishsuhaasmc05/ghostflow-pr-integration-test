from __future__ import annotations
import ast
import re
from pathlib import Path
from .models import ApiRoute, SchemaField, SchemaModel

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "websocket"}


def _route_path(path: str) -> tuple[str, list[str]]:
    params: list[str] = []

    def replace(match: re.Match) -> str:
        params.append(match.group(1))
        return "{}"

    # Normalize {user_id} or {user_id:int} to {}
    re.sub(r"\{([A-Za-z_][\w]*)(?::[^}]+)?\}", replace, path)
    clean_path = re.sub(r"\{([A-Za-z_][\w]*)(?::[^}]+)?\}", r"{\1}", path)
    return (clean_path.rstrip("/") or "/", params)


def _is_pydantic_field_required(node: ast.AnnAssign) -> bool:
    """Determine whether an annotated assignment in a Pydantic model is required."""
    if node.value is None:
        # e.g., name: str (no default) -> required
        return True

    # e.g., name: str = Field(...)
    if isinstance(node.value, ast.Call):
        func_name = ""
        if isinstance(node.value.func, ast.Name):
            func_name = node.value.func.id
        elif isinstance(node.value.func, ast.Attribute):
            func_name = node.value.func.attr

        if func_name == "Field":
            for kw in node.value.keywords:
                if kw.arg in ("default", "default_factory"):
                    if isinstance(kw.value, ast.Constant) and kw.value.value is Ellipsis:
                        return True
                    return False
            # Check first positional arg: Field(...) vs Field(default)
            if node.value.args:
                first_arg = node.value.args[0]
                if isinstance(first_arg, ast.Constant) and first_arg.value is Ellipsis:
                    return True
                return False
            return True

    # e.g., name: str = ...
    if isinstance(node.value, ast.Constant) and node.value.value is Ellipsis:
        return True

    # Any other default value (e.g., None, 0, "", []) makes the field optional in Pydantic
    return False


def extract_backend_models(root: Path) -> dict[str, SchemaModel]:
    """Extract Pydantic BaseModel definitions and their fields across the backend codebase."""
    models: dict[str, SchemaModel] = {}
    if not root.exists():
        return models

    for file in sorted([p.resolve() for p in root.rglob("*.py")]):
        try:
            content = file.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue

        lines = content.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Check if class inherits from BaseModel or another model
            base_names = []
            for b in node.bases:
                if isinstance(b, ast.Name):
                    base_names.append(b.id)
                elif isinstance(b, ast.Attribute):
                    base_names.append(b.attr)

            is_model = any("Model" in b or b in models for b in base_names)
            if not is_model and not any(isinstance(stmt, ast.AnnAssign) for stmt in node.body):
                continue

            fields: dict[str, SchemaField] = {}
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id
                    type_str = ast.unparse(item.annotation) if item.annotation else "Any"
                    is_req = _is_pydantic_field_required(item)

                    # Extract line snippet
                    field_line = item.lineno
                    field_source = lines[field_line - 1].strip()[:240] if 0 < field_line <= len(lines) else ""

                    # Detect field alias from Field(..., alias="...")
                    field_alias = None
                    if isinstance(item.value, ast.Call):
                        for kw in item.value.keywords:
                            if kw.arg == "alias" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                field_alias = kw.value.value

                    # Detect nested model name candidate
                    nested_candidate = re.sub(r"^(?:Optional|list|List|Sequence|set|Set)\[(.*)\]$", r"\1", type_str).strip()
                    nested_candidate = nested_candidate.replace(" | None", "").strip()

                    fields[field_name] = SchemaField(
                        name=field_name,
                        type_name=type_str,
                        is_required=is_req,
                        nested_model=nested_candidate if nested_candidate != type_str and nested_candidate else (type_str if not type_str.islower() else None),
                        file=file.as_posix(),
                        line=field_line,
                        source=field_source,
                        alias=field_alias,
                    )

            model_line = node.lineno
            model_source = lines[model_line - 1].strip()[:240] if 0 < model_line <= len(lines) else ""
            models[node.name] = SchemaModel(
                name=node.name,
                file=file.as_posix(),
                line=model_line,
                source=model_source,
                fields=fields,
            )

    # Link nested_fields where nested_model matches another model
    for model in models.values():
        for field in model.fields.values():
            if field.nested_model and field.nested_model in models:
                field.nested_fields = models[field.nested_model].fields

    return models


def join_path_segments(*parts: str) -> str:
    """Join URL path segments cleanly without duplicate slashes or duplicated overlapping segments."""
    all_segments: list[str] = []
    for part in parts:
        if not part:
            continue
        raw_segments = [s for s in part.strip("/").split("/") if s]
        if not raw_segments:
            continue

        # Check for segment overlap between end of all_segments and start of raw_segments
        max_overlap = min(len(all_segments), len(raw_segments))
        overlap_found = 0
        for k in range(max_overlap, 0, -1):
            if all_segments[-k:] == raw_segments[:k]:
                overlap_found = k
                break

        if overlap_found > 0:
            all_segments.extend(raw_segments[overlap_found:])
        else:
            all_segments.extend(raw_segments)

    if not all_segments:
        return "/"
    return "/" + "/".join(all_segments)


class _ModuleResolver:
    """Resolves Python module and symbol imports within a project backend root."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.py_files: list[Path] = [p.resolve() for p in root.rglob("*.py")] if root.exists() else []
        self._by_rel: dict[str, Path] = {}
        for p in self.py_files:
            try:
                rel = p.relative_to(self.root).as_posix()
                self._by_rel[rel] = p
                if rel.endswith(".py"):
                    self._by_rel[rel[:-3]] = p
                    if rel.endswith("/__init__.py"):
                        self._by_rel[rel[:-12]] = p
            except ValueError:
                pass

    def resolve_import(self, importing_file: Path, module_str: str | None, level: int) -> Path | None:
        """Resolve an import to a target .py file or directory."""
        importing_file = importing_file.resolve()
        if level > 0:
            cur_dir = importing_file.parent
            for _ in range(level - 1):
                cur_dir = cur_dir.parent

            if module_str:
                parts = module_str.split(".")
                cand_file = cur_dir.joinpath(*parts).with_suffix(".py")
                if cand_file.is_file():
                    return cand_file
                cand_init = cur_dir.joinpath(*parts) / "__init__.py"
                if cand_init.is_file():
                    return cand_init
                cand_dir = cur_dir.joinpath(*parts)
                if cand_dir.is_dir():
                    return cand_dir
            else:
                cand_init = cur_dir / "__init__.py"
                if cand_init.is_file():
                    return cand_init
                return cur_dir
            return None

        if not module_str:
            return None

        parts = module_str.split(".")
        # 1. Relative to importing file directory
        cand1 = importing_file.parent.joinpath(*parts).with_suffix(".py")
        if cand1.is_file():
            return cand1.resolve()
        cand1_init = importing_file.parent.joinpath(*parts) / "__init__.py"
        if cand1_init.is_file():
            return cand1_init.resolve()
        cand1_dir = importing_file.parent.joinpath(*parts)
        if cand1_dir.is_dir():
            return cand1_dir.resolve()

        # 2. Relative to project root
        cand2 = self.root.joinpath(*parts).with_suffix(".py")
        if cand2.is_file():
            return cand2.resolve()
        cand2_init = self.root.joinpath(*parts) / "__init__.py"
        if cand2_init.is_file():
            return cand2_init.resolve()
        cand2_dir = self.root.joinpath(*parts)
        if cand2_dir.is_dir():
            return cand2_dir.resolve()

        # 2b. Relative to project parent (e.g. 'from backend.routers.auth ...' when root is backend/)
        if parts and parts[0] == self.root.name and len(parts) > 1:
            cand_stripped = self.root.joinpath(*parts[1:]).with_suffix(".py")
            if cand_stripped.is_file():
                return cand_stripped.resolve()
            cand_stripped_init = self.root.joinpath(*parts[1:]) / "__init__.py"
            if cand_stripped_init.is_file():
                return cand_stripped_init.resolve()
            cand_stripped_dir = self.root.joinpath(*parts[1:])
            if cand_stripped_dir.is_dir():
                return cand_stripped_dir.resolve()

        if self.root.parent:
            cand_parent = self.root.parent.joinpath(*parts).with_suffix(".py")
            if cand_parent.is_file():
                return cand_parent.resolve()
            cand_parent_init = self.root.parent.joinpath(*parts) / "__init__.py"
            if cand_parent_init.is_file():
                return cand_parent_init.resolve()
            cand_parent_dir = self.root.parent.joinpath(*parts)
            if cand_parent_dir.is_dir():
                return cand_parent_dir.resolve()

        # 3. Subdirectories of root (e.g. backend/ or src/ or app/)
        try:
            for sub in self.root.iterdir():
                if sub.is_dir():
                    cand3 = sub.joinpath(*parts).with_suffix(".py")
                    if cand3.is_file():
                        return cand3.resolve()
                    cand3_init = sub.joinpath(*parts) / "__init__.py"
                    if cand3_init.is_file():
                        return cand3_init.resolve()
                    cand3_dir = sub.joinpath(*parts)
                    if cand3_dir.is_dir():
                        return cand3_dir.resolve()
        except OSError:
            pass

        # 4. Lookup by normalized relative path suffix
        mod_suffix = "/".join(parts)
        if mod_suffix in self._by_rel:
            return self._by_rel[mod_suffix].resolve()
        for key, p in self._by_rel.items():
            if key.endswith("/" + mod_suffix) or mod_suffix.endswith("/" + key):
                return p.resolve()

        return None


def extract_backend_routes(root: Path, models: dict[str, SchemaModel] | None = None) -> list[ApiRoute]:
    """Extract FastAPI routes across single-file and cross-file APIRouter / include_router declarations."""
    if models is None:
        models = extract_backend_models(root)

    routes: list[ApiRoute] = []
    if not root.exists():
        return routes

    fastapi_non_payload_types = {
        "Request", "Response", "Depends", "Header", "Query", "Path", "Cookie",
        "BackgroundTasks", "Session", "WebSocket", "HTTPConnection", "Security",
    }

    resolver = _ModuleResolver(root)
    py_files = sorted([p.resolve() for p in root.rglob("*.py")])

    # File-level metadata collected during Pass 1
    file_router_defs: dict[Path, dict[str, str]] = {}  # file -> {router_var: declared_prefix}
    file_app_defs: dict[Path, set[str]] = {}           # file -> {app_var}
    file_imported_symbols: dict[Path, dict[str, tuple[Path, str]]] = {}  # file -> {local_name: (target_file, remote_name)}
    file_imported_modules: dict[Path, dict[str, Path]] = {}              # file -> {local_name: target_file}
    file_include_calls: dict[Path, list[tuple[str, ast.AST, str | None]]] = {}  # file -> list of (caller_name, target_node, prefix)
    file_raw_routes: dict[Path, list[tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef, ast.Call, str]]] = {}

    for file in py_files:
        try:
            content = file.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue

        lines = content.splitlines()

        router_defs: dict[str, str] = {}
        app_defs: set[str] = set()
        imported_symbols: dict[str, tuple[Path, str]] = {}
        imported_modules: dict[str, Path] = {}
        include_calls: list[tuple[str, ast.AST, str | None]] = []
        raw_routes: list[tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef, ast.Call, str]] = []

        # Pass 1a: Imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    resolved = resolver.resolve_import(file, alias.name, 0)
                    if resolved:
                        local_name = alias.asname or alias.name.split(".")[-1]
                        imported_modules[local_name] = resolved
                        if alias.asname:
                            imported_modules[alias.asname] = resolved

            elif isinstance(node, ast.ImportFrom):
                resolved = resolver.resolve_import(file, node.module, node.level)
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    if resolved:
                        sub_dir = resolved.parent if resolved.name == "__init__.py" else (resolved if resolved.is_dir() else None)
                        if sub_dir:
                            cand_sub = sub_dir / f"{alias.name}.py"
                            cand_sub_init = sub_dir / alias.name / "__init__.py"
                            if cand_sub.is_file():
                                imported_modules[local_name] = cand_sub
                            elif cand_sub_init.is_file():
                                imported_modules[local_name] = cand_sub_init
                            else:
                                imported_symbols[local_name] = (resolved, alias.name)
                        else:
                            imported_symbols[local_name] = (resolved, alias.name)

        # Pass 1b: APIRouter and FastAPI instantiations
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                val = node.value
                if isinstance(val, ast.Call):
                    func_name = ""
                    if isinstance(val.func, ast.Name):
                        func_name = val.func.id
                    elif isinstance(val.func, ast.Attribute):
                        func_name = val.func.attr

                    targets = [node.target] if isinstance(node, ast.AnnAssign) else [t for t in node.targets if isinstance(t, ast.Name)]
                    for target in targets:
                        if not isinstance(target, ast.Name):
                            continue
                        var_name = target.id
                        if func_name == "APIRouter":
                            prefix = ""
                            for kw in val.keywords:
                                if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                    prefix = kw.value.value
                            router_defs[var_name] = prefix
                        elif func_name == "FastAPI":
                            app_defs.add(var_name)

        # Pass 1c: include_router calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "include_router":
                    caller_name = ""
                    if isinstance(call.func.value, ast.Name):
                        caller_name = call.func.value.id
                    if call.args:
                        target_node = call.args[0]
                        prefix_val: str | None = ""
                        for kw in call.keywords:
                            if kw.arg == "prefix":
                                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                    prefix_val = kw.value.value
                                else:
                                    prefix_val = None  # Dynamic prefix
                        include_calls.append((caller_name, target_node, prefix_val))

        # Pass 1d: Route handlers
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                    continue

                dec_attr = decorator.func.attr.lower()
                methods_to_add: list[str] = []

                if dec_attr in HTTP_METHODS:
                    methods_to_add = [dec_attr]
                elif dec_attr == "api_route":
                    found_methods: list[str] = []
                    for kw in decorator.keywords:
                        if kw.arg == "methods":
                            if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        m_clean = elt.value.lower()
                                        if m_clean in HTTP_METHODS:
                                            found_methods.append(m_clean)
                    methods_to_add = found_methods if found_methods else ["get"]
                else:
                    continue

                caller_name = ""
                if isinstance(decorator.func.value, ast.Name):
                    caller_name = decorator.func.value.id

                path_str = ""
                has_path = False
                if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                    path_str = decorator.args[0].value
                    has_path = True
                else:
                    for kw in decorator.keywords:
                        if kw.arg == "path" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            path_str = kw.value.value
                            has_path = True

                if not has_path:
                    continue

                line = decorator.lineno
                source = lines[line - 1].strip()[:240] if 0 < line <= len(lines) else ""
                for m in methods_to_add:
                    raw_routes.append((caller_name, path_str, node, decorator, source, m))

        file_router_defs[file] = router_defs
        file_app_defs[file] = app_defs
        file_imported_symbols[file] = imported_symbols
        file_imported_modules[file] = imported_modules
        file_include_calls[file] = include_calls
        file_raw_routes[file] = raw_routes

    # Pass 2: Connect router inclusion edges
    # edges: (parent_file, parent_var) -> list of ((child_file, child_var), edge_prefix)
    edges: dict[tuple[Path, str], list[tuple[tuple[Path, str], str]]] = {}

    for file, calls in file_include_calls.items():
        imp_syms = file_imported_symbols.get(file, {})
        imp_mods = file_imported_modules.get(file, {})
        loc_routers = file_router_defs.get(file, {})

        for caller_name, target_node, prefix_val in calls:
            if prefix_val is None:
                # Dynamic/unresolved prefix: conservative handling, do not invent routes
                continue

            child_target: tuple[Path, str] | None = None

            if isinstance(target_node, ast.Name):
                name = target_node.id
                if name in imp_syms:
                    child_target = imp_syms[name]
                elif name in loc_routers:
                    child_target = (file, name)
                elif name in imp_mods:
                    mod_f = imp_mods[name]
                    target_routers = file_router_defs.get(mod_f, {})
                    if "router" in target_routers:
                        child_target = (mod_f, "router")
                    elif target_routers:
                        child_target = (mod_f, next(iter(target_routers.keys())))

            elif isinstance(target_node, ast.Attribute):
                attr_name = target_node.attr
                val_node = target_node.value
                if isinstance(val_node, ast.Name):
                    v_name = val_node.id
                    if v_name in imp_mods:
                        child_target = (imp_mods[v_name], attr_name)
                    elif v_name in imp_syms:
                        target_f, _ = imp_syms[v_name]
                        child_target = (target_f, attr_name)

            if child_target and caller_name:
                parent_key = (file, caller_name)
                edges.setdefault(parent_key, []).append((child_target, prefix_val))

    # Pass 3: Propagate effective prefixes from apps to routers
    router_effective_prefixes: dict[tuple[Path, str], list[str]] = {}

    all_apps: list[tuple[Path, str]] = []
    for f, apps in file_app_defs.items():
        for a_name in apps:
            all_apps.append((f, a_name))

    if all_apps:
        for app_key in all_apps:
            queue: list[tuple[tuple[Path, str], str]] = [(app_key, "")]
            visited: set[tuple[tuple[Path, str], str]] = set()
            while queue:
                parent_key, current_pfx = queue.pop(0)
                for child_key, edge_pfx in edges.get(parent_key, []):
                    child_decl_pfx = file_router_defs.get(child_key[0], {}).get(child_key[1], "")
                    combined = join_path_segments(current_pfx, edge_pfx, child_decl_pfx)
                    router_effective_prefixes.setdefault(child_key, []).append(combined)
                    v_key = (child_key, combined)
                    if v_key not in visited:
                        visited.add(v_key)
                        queue.append((child_key, combined))
    else:
        # Fallback if no FastAPI app is instantiated in scanned codebase
        all_child_keys = {child for targets in edges.values() for child, _ in targets}
        all_parents = set(edges.keys())
        root_routers = all_parents - all_child_keys
        for r_key in root_routers:
            r_decl = file_router_defs.get(r_key[0], {}).get(r_key[1], "")
            queue = [(r_key, r_decl)]
            visited = set()
            router_effective_prefixes.setdefault(r_key, []).append(r_decl)
            while queue:
                parent_key, current_pfx = queue.pop(0)
                for child_key, edge_pfx in edges.get(parent_key, []):
                    child_decl = file_router_defs.get(child_key[0], {}).get(child_key[1], "")
                    combined = join_path_segments(current_pfx, edge_pfx, child_decl)
                    router_effective_prefixes.setdefault(child_key, []).append(combined)
                    v_key = (child_key, combined)
                    if v_key not in visited:
                        visited.add(v_key)
                        queue.append((child_key, combined))

    # Pass 4: Build ApiRoutes for all discovered endpoints
    raw_route_items: list[ApiRoute] = []

    for file, raw_list in file_raw_routes.items():
        app_set = file_app_defs.get(file, set())
        imp_syms = file_imported_symbols.get(file, {})

        for caller_name, path_str, func_node, decorator, source_snip, method in raw_list:

            response_model_name: str | None = None
            for kw in decorator.keywords:
                if kw.arg == "response_model":
                    response_model_name = ast.unparse(kw.value)

            if not response_model_name and func_node.returns:
                ret_str = ast.unparse(func_node.returns).strip()
                if ret_str not in ("None", "dict", "Any", "Response", "JSONResponse"):
                    response_model_name = ret_str

            applicable_prefixes: list[str]

            if caller_name in app_set:
                applicable_prefixes = [""]
            else:
                target_router_key = (file, caller_name)
                if caller_name in imp_syms:
                    target_router_key = imp_syms[caller_name]

                if target_router_key in router_effective_prefixes:
                    applicable_prefixes = router_effective_prefixes[target_router_key]
                else:
                    # Standalone router not included in any app
                    decl = file_router_defs.get(target_router_key[0], {}).get(target_router_key[1], "")
                    applicable_prefixes = [decl]

            for pfx in applicable_prefixes:
                full_raw_path = join_path_segments(pfx, path_str)
                path, params = _route_path(full_raw_path)

                param_types: dict[str, str] = {}
                request_model_name: str | None = None
                is_auth = False
                req_queries: list[str] = []
                all_queries: list[str] = []

                # Check decorator keywords for security dependencies
                for kw in decorator.keywords:
                    if kw.arg == "dependencies":
                        kw_str = ast.unparse(kw.value).lower()
                        if any(auth_kw in kw_str for auth_kw in ("auth", "user", "token", "security", "bearer", "oauth")):
                            is_auth = True

                num_defaults = len(func_node.args.defaults)
                args_list = func_node.args.args
                arg_defaults: dict[str, str] = {}
                if num_defaults > 0:
                    for arg_item, def_node in zip(args_list[-num_defaults:], func_node.args.defaults):
                        arg_defaults[arg_item.arg] = ast.unparse(def_node)

                for arg in args_list:
                    arg_name = arg.arg
                    if arg_name in ("self", "cls"):
                        continue

                    arg_type = ast.unparse(arg.annotation) if arg.annotation else ""
                    def_val = arg_defaults.get(arg_name)

                    if arg_name in params:
                        param_types[arg_name] = arg_type or "str"
                    else:
                        if any(auth_kw in arg_type.lower() or auth_kw in arg_name.lower() or (def_val and auth_kw in def_val.lower()) for auth_kw in ("current_user", "get_current_user", "auth", "token", "security", "bearer", "oauth", "credential")):
                            is_auth = True

                        if method.upper() in {"POST", "PUT", "PATCH"} and (arg_type in models or (arg_type and not arg_type.islower() and arg_type not in fastapi_non_payload_types)):
                            request_model_name = arg_type
                        else:
                            is_non_query = def_val and any(nq in def_val for nq in ("Header", "Depends", "Security", "Cookie", "Path"))
                            if not is_non_query:
                                all_queries.append(arg_name)
                                if def_val is None or "..." in def_val:
                                    req_queries.append(arg_name)

                line = decorator.lineno

                raw_route_items.append(ApiRoute(
                    method=method.upper(),
                    path=path,
                    file=file.as_posix(),
                    line=line,
                    source=source_snip,
                    path_params=params,
                    path_param_types=param_types,
                    request_model=request_model_name,
                    response_model=response_model_name,
                    request_schema=models.get(request_model_name) if request_model_name else None,
                    response_schema=models.get(response_model_name) if response_model_name else None,
                    query_params=all_queries,
                    required_query_params=req_queries,
                    is_authenticated=is_auth,
                ))

    # Deduplicate exact duplicate route declarations (same method, path, file, line)
    seen_routes: set[tuple[str, str, str, int]] = set()
    routes: list[ApiRoute] = []
    for r in raw_route_items:
        dedup_key = (r.method, r.path, r.file, r.line)
        if dedup_key not in seen_routes:
            seen_routes.add(dedup_key)
            routes.append(r)

    # Also extract Express / Node.js routes if JavaScript/TypeScript backend files exist
    express_routes = _extract_express_routes(root)
    for r in express_routes:
        dedup_key = (r.method, r.path, r.file, r.line)
        if dedup_key not in seen_routes:
            seen_routes.add(dedup_key)
            routes.append(r)

    return routes


def _extract_express_routes(root: Path) -> list[ApiRoute]:
    """Extract Express.js routes (app.get, router.post, etc.) from Node/Express backends.

    Includes multi-file router mount prefix propagation (e.g. app.use('/api', indexRouter)).
    """
    routes: list[ApiRoute] = []
    if not root.exists():
        return routes

    import os
    EXCLUDED = {".git", "node_modules", ".venv", "dist", "build", ".next", "out", "coverage"}
    express_route_re = re.compile(
        r"""\b([A-Za-z0-9_$]+)\.(get|post|put|patch|delete|options|head)\s*\(\s*['"]([^'"]+)['"]""",
        re.IGNORECASE
    )
    require_re = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*require\s*\(\s*['"](\.[^'"]+)['"]\s*\)"""
    )
    import_re = re.compile(
        r"""import\s+(?:(?:\*\s+as\s+([A-Za-z0-9_$]+))|([A-Za-z0-9_$]+))\s+from\s*['"](\.[^'"]+)['"]"""
    )
    mount_re = re.compile(
        r"""\b(?:app|router|server)\.use\s*\(\s*(?:['"]([^'"]+)['"]\s*,\s*)?(?:require\s*\(\s*['"](\.[^'"]+)['"]\s*\)|([A-Za-z0-9_$]+))\s*\)"""
    )

    candidate_files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in (".js", ".ts", ".mjs", ".cjs"):
                candidate_files.append(Path(dirpath) / fname)

    file_info: dict[Path, dict[str, Any]] = {}

    def _resolve_relative_module(from_dir: Path, rel_spec: str) -> Path | None:
        raw = (from_dir / rel_spec).resolve()
        for cand in (
            raw.with_suffix(".js"),
            raw.with_suffix(".ts"),
            raw / "index.js",
            raw / "index.ts",
            raw,
        ):
            if cand.is_file():
                return cand
        return None

    for fpath in candidate_files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Skip pure frontend React component files (containing JSX / React imports without express)
        if ("import React" in content or "from 'react'" in content) and "express" not in content.lower():
            continue

        lines = content.splitlines()
        local_imports: dict[str, Path] = {}
        mounts: list[tuple[str, Path]] = []
        raw_routes: list[dict[str, Any]] = []

        for m in require_re.finditer(content):
            var_name, spec = m.group(1), m.group(2)
            target = _resolve_relative_module(fpath.parent, spec)
            if target:
                local_imports[var_name] = target

        for m in import_re.finditer(content):
            var_name = m.group(1) or m.group(2)
            spec = m.group(3)
            target = _resolve_relative_module(fpath.parent, spec)
            if target and var_name:
                local_imports[var_name] = target

        for m in mount_re.finditer(content):
            prefix = m.group(1) or ""
            inline_req = m.group(2)
            router_var = m.group(3)

            target_path: Path | None = None
            if inline_req:
                target_path = _resolve_relative_module(fpath.parent, inline_req)
            elif router_var and router_var in local_imports:
                target_path = local_imports[router_var]

            if target_path:
                mounts.append((prefix, target_path))

        for m in express_route_re.finditer(content):
            caller = m.group(1).lower()
            method = m.group(2).upper()
            raw_path = m.group(3)

            norm_path = re.sub(r":([A-Za-z0-9_]+)", r"{\1}", raw_path)
            params = re.findall(r"\{([A-Za-z0-9_]+)\}", norm_path)
            lineno = content.count("\n", 0, m.start()) + 1
            snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"{caller}.{method.lower()}('{raw_path}')"

            raw_routes.append({
                "caller": caller,
                "method": method,
                "norm_path": norm_path,
                "lineno": lineno,
                "snippet": snippet,
                "params": params,
            })

        file_info[fpath] = {
            "routes": raw_routes,
            "local_imports": local_imports,
            "mounts": mounts,
        }

    file_effective_prefixes: dict[Path, list[str]] = {}
    for parent_fpath, data in file_info.items():
        for prefix, target_file in data["mounts"]:
            file_effective_prefixes.setdefault(target_file, []).append(prefix)

    for fpath, data in file_info.items():
        applicable_prefixes = file_effective_prefixes.get(fpath, [""])
        for r in data["routes"]:
            caller = r["caller"]
            base_norm = r["norm_path"]

            if caller in ("app", "server"):
                routes.append(ApiRoute(
                    method=r["method"],
                    path=base_norm,
                    file=fpath.as_posix(),
                    line=r["lineno"],
                    source=r["snippet"],
                    path_params=r["params"],
                    path_param_types={p: "string" for p in r["params"]},
                ))
            else:
                for pfx in applicable_prefixes:
                    eff_path = join_path_segments(pfx, base_norm) if pfx else base_norm
                    routes.append(ApiRoute(
                        method=r["method"],
                        path=eff_path,
                        file=fpath.as_posix(),
                        line=r["lineno"],
                        source=r["snippet"],
                        path_params=r["params"],
                        path_param_types={p: "string" for p in r["params"]},
                    ))

    return routes
