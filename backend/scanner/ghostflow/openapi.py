from __future__ import annotations
import json
import hashlib
import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # Fallback handled safely

from .models import (
    ApiCall,
    ApiRoute,
    Evidence,
    OpenApiDisagreement,
    OpenApiSpecInfo,
    SchemaField,
    SchemaModel,
    Severity,
)
from .compatibility import are_types_compatible, map_py_to_ts, parse_type_info

# Common conventional specification locations
CONVENTIONAL_SPEC_NAMES = (
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
)

CONVENTIONAL_DIRS = (
    "",
    "docs",
    "api",
    "spec",
    "specs",
    ".ghostflow",
    "openapi",
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def _normalise_path(path: str) -> str:
    """Normalize route path for consistent cross-layer comparison."""
    clean = path.split("?")[0] if "?" in path else path
    return re.sub(r"\{[^{}]+\}", "{}", clean).rstrip("/") or "/"


def _normalise_file(filepath: str) -> str:
    p = filepath.replace("\\", "/").strip()
    return p.split("/")[-1] if "/" in p else p


def find_conventional_spec(project_dir: Path) -> Path | None:
    """Safely discover a conventional OpenAPI/Swagger specification file within project directory."""
    proj = project_dir.resolve()
    if not proj.is_dir():
        return None

    for sub in CONVENTIONAL_DIRS:
        folder = proj / sub if sub else proj
        if not folder.is_dir():
            continue
        for name in CONVENTIONAL_SPEC_NAMES:
            cand = folder / name
            try:
                # Ensure resolved candidate is strictly within project root
                resolved = cand.resolve()
                if resolved.is_file() and (resolved == proj or proj in resolved.parents):
                    return resolved
            except (OSError, ValueError):
                continue
    return None


def safe_load_spec(file_path: Path, max_bytes: int = 10 * 1024 * 1024) -> tuple[dict[str, Any], str, str]:
    """
    Safely read and validate an OpenAPI or Swagger file.
    Returns (spec_dict, spec_format, spec_version).
    Enforces maximum file size to protect against memory exhaustion.
    """
    resolved = file_path.resolve()
    if not resolved.is_file():
        raise ValueError(f"Specification file not found: {file_path}")

    size = resolved.stat().st_size
    if size > max_bytes:
        raise ValueError(f"Specification file exceeds maximum allowed size ({max_bytes // (1024 * 1024)} MB): {size} bytes")

    try:
        content = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Specification file must be valid UTF-8 text: {exc}") from exc

    doc: Any = None
    fmt = "json"

    # Attempt JSON first if extension is .json or starts with '{'
    stripped = content.strip()
    if resolved.suffix.lower() == ".json" or stripped.startswith("{"):
        try:
            doc = json.loads(content)
            fmt = "json"
        except json.JSONDecodeError as json_exc:
            # If explicit .json failed, report clear error
            if resolved.suffix.lower() == ".json":
                raise ValueError(f"Invalid JSON in specification file: {json_exc}") from json_exc

    # Attempt YAML if JSON not parsed
    if doc is None:
        if yaml is None:
            raise ValueError("PyYAML is required to parse YAML specifications but is not available.")
        try:
            doc = yaml.safe_load(content)
            fmt = "yaml"
        except Exception as yaml_exc:
            raise ValueError(f"Failed to parse specification file as JSON or YAML: {yaml_exc}") from yaml_exc

    if not isinstance(doc, dict):
        raise ValueError("Specification root must be a valid mapping / object.")

    # Validate specification version
    spec_version: str
    if "openapi" in doc:
        ver = str(doc["openapi"]).strip()
        if not (ver.startswith("3.0") or ver.startswith("3.1")):
            raise ValueError(f"Unsupported OpenAPI version '{ver}'. Supported versions: OpenAPI 3.0.x and 3.1.x.")
        spec_version = ver
    elif "swagger" in doc:
        ver = str(doc["swagger"]).strip()
        if ver != "2.0":
            raise ValueError(f"Unsupported Swagger version '{ver}'. Only Swagger 2.0 is supported.")
        spec_version = f"Swagger {ver}"
    else:
        raise ValueError("Invalid specification format: Missing top-level 'openapi' or 'swagger' version identifier.")

    return doc, fmt, spec_version


def resolve_local_ref(root_doc: dict[str, Any], ref: str, visited: set[str], depth: int = 0) -> dict[str, Any] | None:
    """Resolve a local JSON Pointer ($ref) safely preventing circular reference recursion."""
    if depth > 15 or ref in visited:
        # Return circular reference stub to avoid infinite loops
        return {"type": "object", "title": "CircularRef", "_circular": True}

    if not ref.startswith("#/"):
        # Remote external references are unsupported conservatively
        return None

    visited.add(ref)
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in ref[2:].split("/")]
    cur: Any = root_doc
    for t in tokens:
        if isinstance(cur, dict) and t in cur:
            cur = cur[t]
        else:
            return None

    if isinstance(cur, dict) and "$ref" in cur and isinstance(cur["$ref"], str):
        return resolve_local_ref(root_doc, cur["$ref"], visited, depth + 1)

    return cur if isinstance(cur, dict) else None


def _map_openapi_type(schema: dict[str, Any], root_doc: dict[str, Any], visited: set[str], depth: int = 0) -> str:
    """Map OpenAPI schema type to TypeScript / Python compatible type string."""
    if depth > 10:
        return "any"

    if "$ref" in schema and isinstance(schema["$ref"], str):
        ref = schema["$ref"]
        resolved = resolve_local_ref(root_doc, ref, visited, depth + 1)
        if resolved:
            if resolved.get("_circular"):
                return ref.split("/")[-1]
            return _map_openapi_type(resolved, root_doc, visited, depth + 1)
        return ref.split("/")[-1]

    # Handle composition: anyOf, oneOf, allOf
    if "allOf" in schema and isinstance(schema["allOf"], list):
        # Merged object representation
        types = [_map_openapi_type(s, root_doc, visited, depth + 1) for s in schema["allOf"] if isinstance(s, dict)]
        return " & ".join(types) if types else "object"

    if "oneOf" in schema and isinstance(schema["oneOf"], list):
        types = [_map_openapi_type(s, root_doc, visited, depth + 1) for s in schema["oneOf"] if isinstance(s, dict)]
        return " | ".join(types) if types else "any"

    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        types = [_map_openapi_type(s, root_doc, visited, depth + 1) for s in schema["anyOf"] if isinstance(s, dict)]
        return " | ".join(types) if types else "any"

    raw_type = schema.get("type", "object")
    is_nullable = bool(schema.get("nullable", False))

    res_type: str
    if raw_type == "integer":
        res_type = "int"
    elif raw_type == "number":
        res_type = "float"
    elif raw_type == "boolean":
        res_type = "boolean"
    elif raw_type == "string":
        fmt = schema.get("format", "")
        if fmt in ("date", "date-time"):
            res_type = "string"
        else:
            res_type = "string"
    elif raw_type == "array":
        items = schema.get("items", {})
        inner = _map_openapi_type(items, root_doc, visited, depth + 1) if isinstance(items, dict) else "any"
        res_type = f"{inner}[]"
    elif raw_type == "object":
        title = schema.get("title")
        res_type = title if title else "object"
    else:
        res_type = str(raw_type)

    if is_nullable:
        res_type = f"{res_type} | None"

    return res_type


def _extract_schema_fields(
    schema: dict[str, Any],
    root_doc: dict[str, Any],
    spec_path: str,
    visited: set[str] | None = None,
    depth: int = 0,
) -> dict[str, SchemaField]:
    """Recursively extract fields from an OpenAPI schema definition."""
    if depth > 10:
        return {}
    if visited is None:
        visited = set()

    fields: dict[str, SchemaField] = {}

    if "$ref" in schema and isinstance(schema["$ref"], str):
        ref = schema["$ref"]
        resolved = resolve_local_ref(root_doc, ref, visited, depth + 1)
        if resolved and not resolved.get("_circular"):
            return _extract_schema_fields(resolved, root_doc, spec_path, visited, depth + 1)
        return {}

    # Handle allOf composition by merging properties
    if "allOf" in schema and isinstance(schema["allOf"], list):
        for sub in schema["allOf"]:
            if isinstance(sub, dict):
                sub_fields = _extract_schema_fields(sub, root_doc, spec_path, visited, depth + 1)
                fields.update(sub_fields)
        return fields

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return fields

    required_props = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()

    for prop_name, prop_def in properties.items():
        if not isinstance(prop_def, dict):
            continue

        type_str = _map_openapi_type(prop_def, root_doc, set(visited), depth + 1)
        is_req = prop_name in required_props

        # Check for nested model
        nested_fields = None
        if prop_def.get("type") == "object" or "properties" in prop_def or "$ref" in prop_def:
            nested_fields = _extract_schema_fields(prop_def, root_doc, spec_path, set(visited), depth + 1)

        fields[prop_name] = SchemaField(
            name=prop_name,
            type_name=type_str,
            is_required=is_req,
            file=spec_path,
            line=1,
            source=f"{prop_name}: {type_str}",
            nested_fields=nested_fields or None,
        )

    return fields


class OpenApiOperation:
    def __init__(
        self,
        method: str,
        path: str,
        operation_id: str | None,
        summary: str | None,
        path_params: list[str],
        path_param_types: dict[str, str],
        query_params: list[str],
        query_param_types: dict[str, str],
        required_query_params: list[str],
        request_schema: SchemaModel | None,
        response_schemas: dict[str, SchemaModel],
        spec_location: str,
    ):
        self.method = method
        self.path = path
        self.normalized_path = _normalise_path(path)
        self.operation_id = operation_id
        self.summary = summary
        self.path_params = path_params
        self.path_param_types = path_param_types
        self.query_params = query_params
        self.query_param_types = query_param_types
        self.required_query_params = required_query_params
        self.request_schema = request_schema
        self.response_schemas = response_schemas
        self.spec_location = spec_location


def extract_openapi_operations(root_doc: dict[str, Any], spec_file_path: str) -> list[OpenApiOperation]:
    """Extract structured operations and contracts from an OpenAPI or Swagger document."""
    operations: list[OpenApiOperation] = []
    paths = root_doc.get("paths", {})
    if not isinstance(paths, dict):
        return operations

    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Shared path-level parameters
        shared_params = path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []

        for method_name, op_item in path_item.items():
            method_lower = method_name.lower()
            if method_lower not in HTTP_METHODS or not isinstance(op_item, dict):
                continue

            method = method_lower.upper()
            op_id = op_item.get("operationId")
            summary = op_item.get("summary")

            all_params = list(shared_params) + (op_item.get("parameters", []) if isinstance(op_item.get("parameters"), list) else [])

            path_params: list[str] = []
            path_param_types: dict[str, str] = {}
            query_params: list[str] = []
            query_param_types: dict[str, str] = {}
            req_query_params: list[str] = []

            for param in all_params:
                if not isinstance(param, dict):
                    continue
                if "$ref" in param:
                    resolved_p = resolve_local_ref(root_doc, param["$ref"], set())
                    if isinstance(resolved_p, dict):
                        param = resolved_p

                p_in = param.get("in")
                p_name = param.get("name")
                if not p_name:
                    continue

                schema_node = param.get("schema", param)
                ptype = _map_openapi_type(schema_node, root_doc, set()) if isinstance(schema_node, dict) else "string"
                is_req = bool(param.get("required", False))

                if p_in == "path":
                    path_params.append(p_name)
                    path_param_types[p_name] = ptype
                elif p_in == "query":
                    query_params.append(p_name)
                    query_param_types[p_name] = ptype
                    if is_req:
                        req_query_params.append(p_name)

            # Request body extraction (OpenAPI 3.x vs Swagger 2.0)
            request_schema: SchemaModel | None = None
            req_body = op_item.get("requestBody")
            if isinstance(req_body, dict):
                if "$ref" in req_body:
                    res_rb = resolve_local_ref(root_doc, req_body["$ref"], set())
                    if isinstance(res_rb, dict):
                        req_body = res_rb
                content = req_body.get("content", {})
                if isinstance(content, dict):
                    # Prefer application/json
                    json_media = content.get("application/json") or next(iter(content.values()), None)
                    if isinstance(json_media, dict) and "schema" in json_media and isinstance(json_media["schema"], dict):
                        fields = _extract_schema_fields(json_media["schema"], root_doc, spec_file_path)
                        s_name = json_media["schema"].get("title") or f"{op_id or method}Request"
                        request_schema = SchemaModel(
                            name=s_name,
                            file=spec_file_path,
                            line=1,
                            source=f"requestBody: {s_name}",
                            fields=fields,
                        )
            elif method in {"POST", "PUT", "PATCH"}:
                # Swagger 2.0 body parameter fallback
                for param in all_params:
                    if isinstance(param, dict) and param.get("in") == "body" and "schema" in param and isinstance(param["schema"], dict):
                        fields = _extract_schema_fields(param["schema"], root_doc, spec_file_path)
                        s_name = param["schema"].get("title") or f"{op_id or method}Request"
                        request_schema = SchemaModel(
                            name=s_name,
                            file=spec_file_path,
                            line=1,
                            source=f"body param: {s_name}",
                            fields=fields,
                        )
                        break

            # Response schemas
            response_schemas: dict[str, SchemaModel] = {}
            responses = op_item.get("responses", {})
            if isinstance(responses, dict):
                for status_code, resp_item in responses.items():
                    if not isinstance(resp_item, dict):
                        continue
                    if "$ref" in resp_item:
                        res_resp = resolve_local_ref(root_doc, resp_item["$ref"], set())
                        if isinstance(res_resp, dict):
                            resp_item = res_resp

                    schema_node = None
                    if "content" in resp_item and isinstance(resp_item["content"], dict):
                        json_resp = resp_item["content"].get("application/json") or next(iter(resp_item["content"].values()), None)
                        if isinstance(json_resp, dict):
                            schema_node = json_resp.get("schema")
                    elif "schema" in resp_item and isinstance(resp_item["schema"], dict):
                        schema_node = resp_item["schema"]

                    if isinstance(schema_node, dict):
                        resp_fields = _extract_schema_fields(schema_node, root_doc, spec_file_path)
                        resp_title = schema_node.get("title") or f"{op_id or method}Response{status_code}"
                        response_schemas[str(status_code)] = SchemaModel(
                            name=resp_title,
                            file=spec_file_path,
                            line=1,
                            source=f"response {status_code}: {resp_title}",
                            fields=resp_fields,
                        )

            spec_loc = f"paths['{raw_path}'].{method.lower()}"
            operations.append(OpenApiOperation(
                method=method,
                path=raw_path,
                operation_id=op_id,
                summary=summary,
                path_params=path_params,
                path_param_types=path_param_types,
                query_params=query_params,
                query_param_types=query_param_types,
                required_query_params=req_query_params,
                request_schema=request_schema,
                response_schemas=response_schemas,
                spec_location=spec_loc,
            ))

    return operations


def cross_validate_openapi(
    calls: list[ApiCall],
    routes: list[ApiRoute],
    operations: list[OpenApiOperation],
    spec_info: OpenApiSpecInfo,
    existing_finding_ids: set[str] | None = None,
) -> list[OpenApiDisagreement]:
    """
    Cross-validate extracted frontend calls and backend routes against the OpenAPI specification.
    Returns a distinct list of OpenApiDisagreement items kept separate from confirmed source-to-source findings.
    """
    disagreements: list[OpenApiDisagreement] = []
    seen_ids: set[str] = set()

    spec_by_key: dict[tuple[str, str], OpenApiOperation] = {}
    spec_by_path: dict[str, list[OpenApiOperation]] = {}
    for op in operations:
        spec_by_key[(op.method, op.normalized_path)] = op
        spec_by_path.setdefault(op.normalized_path, []).append(op)

    # 1. OAS001: Frontend calls missing from specification
    # Flagged when frontend calls an endpoint not declared in the specification
    for call in calls:
        if getattr(call, "is_dynamic", False) or call.path == "<unresolved>" or not call.path.startswith("/"):
            continue

        norm_path = _normalise_path(call.path)
        key = (call.method, norm_path)
        matching_op = spec_by_key.get(key)

        if not matching_op:
            path_ops = spec_by_path.get(norm_path, [])
            if not path_ops:
                fid = hashlib.sha1(f"OAS001:{call.method}:{norm_path}:{_normalise_file(call.file)}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    ev_call = Evidence(role="frontend", file=call.file, line=call.line, source=call.source)
                    ev_spec = Evidence(role="specification", file=spec_info.path, line=1, source=f"OpenAPI spec ({spec_info.title})")
                    disagreements.append(OpenApiDisagreement(
                        id=fid,
                        rule_id="OAS001",
                        title="Frontend call missing from OpenAPI specification",
                        severity="low",
                        confidence=0.75,
                        category="Specification Coverage",
                        message=f"Frontend calls {call.method} {call.path}, but this operation is not declared in the OpenAPI specification ({spec_info.title}).",
                        recommendation="Add this operation to the OpenAPI specification, or verify if the frontend call targets an undocumented endpoint.",
                        uncertainty_note="The OpenAPI specification may be incomplete, private, or lagging behind active frontend feature development.",
                        evidence=[ev_call, ev_spec],
                        details={"method": call.method, "path": call.path, "normalized_path": norm_path, "spec_path": spec_info.path},
                    ))
            else:
                # OAS003: Method mismatch between frontend call and specification
                avail_methods = ", ".join(sorted(o.method for o in path_ops))
                fid = hashlib.sha1(f"OAS003:{call.method}:{norm_path}:{_normalise_file(call.file)}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    ev_call = Evidence(role="frontend", file=call.file, line=call.line, source=call.source)
                    ev_spec = Evidence(role="specification", file=spec_info.path, line=1, source=f"Specification declares: {avail_methods}")
                    disagreements.append(OpenApiDisagreement(
                        id=fid,
                        rule_id="OAS003",
                        title="HTTP method disagreement with specification",
                        severity="medium",
                        confidence=0.82,
                        category="Specification Consistency",
                        message=f"Frontend calls {call.method} {call.path}, but the OpenAPI specification declares this path with method(s): {avail_methods}.",
                        recommendation=f"Update the frontend HTTP method or align the specification path {norm_path} to support {call.method}.",
                        uncertainty_note="Verify whether the specification intentionally restricts this method or requires updating.",
                        evidence=[ev_call, ev_spec],
                        details={"call_method": call.method, "spec_methods": avail_methods, "path": call.path},
                    ))

    # 2. OAS002: Specification operation not implemented in backend source
    # Flagged when the specification declares an endpoint that has no discovered route in backend code
    route_keys = {(r.method, _normalise_path(r.path)) for r in routes}
    route_paths = {_normalise_path(r.path) for r in routes}

    for op in operations:
        key = (op.method, op.normalized_path)
        if key not in route_keys and op.normalized_path not in route_paths:
            fid = hashlib.sha1(f"OAS002:{op.method}:{op.normalized_path}".encode()).hexdigest()[:12]
            if fid not in seen_ids:
                seen_ids.add(fid)
                ev_spec = Evidence(role="specification", file=spec_info.path, line=1, source=f"{op.method} {op.path} ({op.spec_location})")
                disagreements.append(OpenApiDisagreement(
                    id=fid,
                    rule_id="OAS002",
                    title="Specification operation not implemented in backend",
                    severity="low",
                    confidence=0.72,
                    category="Specification Coverage",
                    message=f"OpenAPI specification defines {op.method} {op.path}, but no corresponding backend route was found in the source code.",
                    recommendation="Implement the backend endpoint or remove deprecated/planned operations from the specification.",
                    uncertainty_note="The specification may define planned endpoints not yet implemented, or routes registered via dynamic mechanisms.",
                    evidence=[ev_spec],
                    details={"method": op.method, "path": op.path, "operation_id": op.operation_id, "spec_location": op.spec_location},
                ))

    # 3. OAS006: Path parameter inconsistencies with specification
    for op in operations:
        key = (op.method, op.normalized_path)
        matching_routes = [r for r in routes if r.method == op.method and _normalise_path(r.path) == op.normalized_path]
        for route in matching_routes:
            if op.path_params and route.path_params and op.path_params != route.path_params:
                fid = hashlib.sha1(f"OAS006:{op.method}:{op.normalized_path}:{_normalise_file(route.file)}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    ev_route = Evidence(role="backend", file=route.file, line=route.line, source=route.source)
                    ev_spec = Evidence(role="specification", file=spec_info.path, line=1, source=f"Spec path params: {op.path_params}")
                    disagreements.append(OpenApiDisagreement(
                        id=fid,
                        rule_id="OAS006",
                        title="Path parameter naming inconsistency with specification",
                        severity="medium",
                        confidence=0.80,
                        category="Specification Consistency",
                        message=f"Backend route declares path parameter(s) {route.path_params}, while OpenAPI specification defines {op.path_params} on {op.method} {op.path}.",
                        recommendation="Align backend path parameter names with the OpenAPI specification.",
                        uncertainty_note="Parameter naming differences may affect client SDK generation and documentation accuracy.",
                        evidence=[ev_route, ev_spec],
                        details={"backend_params": route.path_params, "spec_params": op.path_params, "path": op.path},
                    ))

    # 4. OAS004: Request schema disagreements with specification
    for op in operations:
        if not op.request_schema:
            continue
        key = (op.method, op.normalized_path)
        matching_routes = [r for r in routes if r.method == op.method and _normalise_path(r.path) == op.normalized_path]

        for route in matching_routes:
            if not route.request_schema:
                continue

            for spec_field_name, spec_field in op.request_schema.fields.items():
                if spec_field.is_required and spec_field_name not in route.request_schema.fields:
                    fid = hashlib.sha1(f"OAS004:req_missing:{op.method}:{op.normalized_path}:{spec_field_name}".encode()).hexdigest()[:12]
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        ev_route = Evidence(role="backend", file=route.file, line=route.line, source=route.source)
                        ev_spec = Evidence(role="specification", file=spec_info.path, line=1, source=f"Required in spec: {spec_field_name} ({spec_field.type_name})")
                        disagreements.append(OpenApiDisagreement(
                            id=fid,
                            rule_id="OAS004",
                            title="Backend request schema missing field required by specification",
                            severity="medium",
                            confidence=0.85,
                            category="Schema Disagreement",
                            message=f"OpenAPI specification requires request field '{spec_field_name}' ({spec_field.type_name}) for {op.method} {op.path}, but backend model '{route.request_schema.name}' does not declare it.",
                            recommendation=f"Add '{spec_field_name}' to backend model '{route.request_schema.name}' or mark it optional in the specification.",
                            uncertainty_note="Verify whether the specification reflects an upcoming API revision.",
                            evidence=[ev_route, ev_spec],
                            details={"field": spec_field_name, "spec_type": spec_field.type_name, "path": op.path},
                        ))

    # 5. OAS005: Response schema disagreements with specification
    for op in operations:
        if not op.response_schemas:
            continue
        key = (op.method, op.normalized_path)
        matching_routes = [r for r in routes if r.method == op.method and _normalise_path(r.path) == op.normalized_path]

        # Use 200/201 response schema as primary comparison
        spec_resp = op.response_schemas.get("200") or op.response_schemas.get("201") or next(iter(op.response_schemas.values()), None)
        if not spec_resp:
            continue

        for route in matching_routes:
            if not route.response_schema:
                continue

            for spec_field_name, spec_field in spec_resp.fields.items():
                if spec_field.is_required and spec_field_name not in route.response_schema.fields:
                    fid = hashlib.sha1(f"OAS005:res_missing:{op.method}:{op.normalized_path}:{spec_field_name}".encode()).hexdigest()[:12]
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        ev_route = Evidence(role="backend", file=route.file, line=route.line, source=route.source)
                        ev_spec = Evidence(role="specification", file=spec_info.path, line=1, source=f"Documented in spec: {spec_field_name} ({spec_field.type_name})")
                        disagreements.append(OpenApiDisagreement(
                            id=fid,
                            rule_id="OAS005",
                            title="Backend response schema missing field documented in specification",
                            severity="low",
                            confidence=0.78,
                            category="Schema Disagreement",
                            message=f"OpenAPI specification documents response field '{spec_field_name}' ({spec_field.type_name}) on {op.method} {op.path}, but backend model '{route.response_schema.name}' does not return it.",
                            recommendation=f"Update backend model '{route.response_schema.name}' to include '{spec_field_name}' or remove it from the specification.",
                            uncertainty_note="The specification may describe response envelopes or optional extensions.",
                            evidence=[ev_route, ev_spec],
                            details={"field": spec_field_name, "spec_type": spec_field.type_name, "path": op.path},
                        ))

    return disagreements
