from __future__ import annotations
import hashlib
import re
from pathlib import Path
from typing import Any
from .models import ApiCall, ApiRoute, Evidence, Finding, SchemaField, SchemaModel
from .compatibility import are_types_compatible, map_py_to_ts, parse_type_info


def _normalise(path: str) -> str:
    clean = path.split("?")[0] if "?" in path else path
    return re.sub(r"\{[^{}]+\}", "{}", clean).rstrip("/") or "/"


def _normalise_file(filepath: str) -> str:
    """Normalize file path for stable hash generation across platforms and relative paths."""
    p = filepath.replace("\\", "/").strip()
    return p.split("/")[-1] if "/" in p else p


# Standard candidate prefixes for cross-layer prefix drift (INT001)
_DEFAULT_PREFIXES: tuple[str, ...] = (
    "/api/v1",
    "/api/v2",
    "/api",
    "/v1",
    "/v2",
)


def _get_candidate_prefixes(routes: list[ApiRoute]) -> list[str]:
    """Collect standard and statically discovered backend router prefixes."""
    prefixes = list(_DEFAULT_PREFIXES)
    seen = set(prefixes)
    for r in routes:
        parts = [p for p in r.path.split("/") if p and not p.startswith("{")]
        if len(parts) >= 2:
            cand = f"/{parts[0]}/{parts[1]}"
            if cand not in seen and len(cand) <= 30:
                seen.add(cand)
                prefixes.append(cand)
        if len(parts) >= 1:
            cand = f"/{parts[0]}"
            if cand not in seen and len(cand) <= 20:
                seen.add(cand)
                prefixes.append(cand)
    prefixes.sort(key=lambda p: (len(p.split("/")), len(p)), reverse=True)
    return prefixes


def _find_prefix_drift_match(
    call: ApiCall, routes: list[ApiRoute]
) -> tuple[ApiRoute, str, str] | None:
    """Find an unambiguous prefix drift match for call against routes.

    Returns (matching_route, prefix, direction) or None.
    Directions: 'frontend_has_prefix' or 'backend_has_prefix'.
    """
    call_norm = _normalise(call.path)
    prefixes = _get_candidate_prefixes(routes)

    candidates: list[tuple[str, ApiRoute, str, str]] = []

    for prefix in prefixes:
        # Direction 1: frontend_has_prefix (call has prefix, route does not)
        stripped: str | None = None
        if call_norm == prefix:
            stripped = "/"
        elif call_norm.startswith(prefix + "/"):
            stripped = call_norm[len(prefix):]

        if stripped:
            matching_routes = [
                r for r in routes
                if r.method == call.method and _normalise(r.path) == stripped
            ]
            for r in matching_routes:
                candidates.append((_normalise(r.path), r, prefix, "frontend_has_prefix"))

        # Direction 2: backend_has_prefix (call lacks prefix, route has it)
        target = (prefix + call_norm) if call_norm != "/" else prefix
        matching_routes = [
            r for r in routes
            if r.method == call.method and _normalise(r.path) == target
        ]
        for r in matching_routes:
            candidates.append((_normalise(r.path), r, prefix, "backend_has_prefix"))

    if not candidates:
        return None

    # Ambiguity check: all candidates must point to the same target route shape and direction
    distinct_target_shapes = {c[0] for c in candidates}
    distinct_directions = {c[3] for c in candidates}

    if len(distinct_target_shapes) > 1 or len(distinct_directions) > 1:
        # Multiple different routes or conflicting directions -> ambiguous, do not emit INT001
        return None

    best = candidates[0]
    return (best[1], best[2], best[3])


def _compare_request_fields(
    fe_fields: dict[str, SchemaField],
    be_fields: dict[str, SchemaField],
    call: ApiCall,
    route: ApiRoute,
    prefix: str = "",
) -> list[Finding]:
    """Compare request schema fields recursively for missing required fields, type mismatches, and optionality."""
    findings: list[Finding] = []
    call_evidence = Evidence(role="frontend", file=call.file, line=call.line, source=call.source)

    # 1. Missing required fields in frontend payload
    for be_name, be_field in be_fields.items():
        wire_name = getattr(be_field, "alias", None) or be_name
        full_name = f"{prefix}{wire_name}"
        # Match either wire name (alias) or raw backend field name
        has_fe = wire_name in fe_fields or be_name in fe_fields
        if be_field.is_required and not has_fe:
            be_evidence = Evidence(
                role="backend",
                file=be_field.file or route.file,
                line=be_field.line or route.line,
                source=be_field.source or route.source,
            )
            rule = "API005"
            fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{full_name}".encode()).hexdigest()[:12]
            ts_suggestion = map_py_to_ts(be_field.type_name)
            model_name = route.request_schema.name if route.request_schema else "RequestModel"
            findings.append(Finding(
                id=fid,
                rule_id=rule,
                title="Request payload missing required field",
                severity="high",
                confidence=0.92,
                category="Request Schema",
                message=f"Frontend request payload for {call.method} {call.path} is missing required field '{full_name}' ({be_field.type_name}) expected by backend model '{model_name}'.",
                recommendation=f"Add '{wire_name}: {ts_suggestion}' to the frontend request payload type, or provide a default value in the backend model.",
                evidence=[call_evidence, be_evidence],
                details={
                    "field": full_name,
                    "expected_type": be_field.type_name,
                    "model": model_name,
                    "method": call.method,
                    "path": call.path,
                    "normalized_path": _normalise(call.path),
                },
            ))

    # 2. Check fields present in both for type compatibility, optionality, and nested structures
    for field_name, fe_field in fe_fields.items():
        # Find corresponding backend field by direct name or alias
        be_field = None
        if field_name in be_fields:
            be_field = be_fields[field_name]
        else:
            for bf in be_fields.values():
                if getattr(bf, "alias", None) == field_name:
                    be_field = bf
                    break
        if not be_field:
            continue
        full_name = f"{prefix}{field_name}"

        fe_ev = Evidence(
            role="frontend",
            file=fe_field.file or call.file,
            line=fe_field.line or call.line,
            source=fe_field.source or call.source,
        )
        be_ev = Evidence(
            role="backend",
            file=be_field.file or route.file,
            line=be_field.line or route.line,
            source=be_field.source or route.source,
        )

        # Check nested schemas
        if fe_field.nested_fields and be_field.nested_fields:
            nested_findings = _compare_request_fields(
                fe_field.nested_fields,
                be_field.nested_fields,
                call,
                route,
                prefix=f"{full_name}.",
            )
            findings.extend(nested_findings)
            continue

        # Check primitive / compound type compatibility
        is_compat, reason = are_types_compatible(fe_field.type_name, be_field.type_name)
        if not is_compat:
            rule = "API006"
            fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{full_name}".encode()).hexdigest()[:12]
            ts_suggestion = map_py_to_ts(be_field.type_name)
            model_name = route.request_schema.name if route.request_schema else "RequestModel"
            findings.append(Finding(
                id=fid,
                rule_id=rule,
                title="Request payload field type mismatch",
                severity="high",
                confidence=0.90,
                category="Request Schema",
                message=f"Request payload field '{full_name}' type mismatch on {call.method} {call.path}: frontend sends '{fe_field.type_name}', but backend model '{model_name}' expects '{be_field.type_name}'.",
                recommendation=f"Update '{field_name}' in frontend request type to '{ts_suggestion}', or adjust backend field '{be_name}' to accept '{fe_field.type_name}'.",
                evidence=[fe_ev, be_ev],
                details={
                    "field": full_name,
                    "frontend_type": fe_field.type_name,
                    "backend_type": be_field.type_name,
                    "method": call.method,
                    "path": call.path,
                    "normalized_path": _normalise(call.path),
                },
            ))
        elif be_field.is_required and not fe_field.is_required:
            # Frontend marked a required backend field as optional
            rule = "API009"
            fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{full_name}:req".encode()).hexdigest()[:12]
            findings.append(Finding(
                id=fid,
                rule_id=rule,
                title="Request payload optionality mismatch",
                severity="medium",
                confidence=0.84,
                category="Schema Nullability",
                message=f"Field '{full_name}' is optional in frontend request, but backend model '{route.request_schema.name if route.request_schema else 'RequestModel'}' requires it. Sending undefined may cause runtime 422 errors.",
                recommendation=f"Mark '{field_name}' as required in the frontend request type, or assign a default value to the backend field.",
                evidence=[fe_ev, be_ev],
                details={
                    "field": full_name,
                    "frontend_required": False,
                    "backend_required": True,
                    "method": call.method,
                    "path": call.path,
                    "normalized_path": _normalise(call.path),
                },
            ))

    return findings


def _compare_response_fields(
    fe_fields: dict[str, SchemaField],
    be_fields: dict[str, SchemaField],
    call: ApiCall,
    route: ApiRoute,
    prefix: str = "",
) -> list[Finding]:
    """Compare response schema fields recursively for missing fields, type mismatches, and nullability."""
    findings: list[Finding] = []
    call_evidence = Evidence(role="frontend", file=call.file, line=call.line, source=call.source)

    # 1. Missing fields expected by frontend
    for fe_name, fe_field in fe_fields.items():
        full_name = f"{prefix}{fe_name}"
        be_match = None
        if fe_name in be_fields:
            be_match = be_fields[fe_name]
        else:
            for bf in be_fields.values():
                if getattr(bf, "alias", None) == fe_name:
                    be_match = bf
                    break

        if fe_field.is_required and be_match is None:
            fe_ev = Evidence(
                role="frontend",
                file=fe_field.file or call.file,
                line=fe_field.line or call.line,
                source=fe_field.source or call.source,
            )
            be_ev = Evidence(
                role="backend",
                file=route.file,
                line=route.line,
                source=route.source,
            )
            rule = "API007"
            fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{full_name}".encode()).hexdigest()[:12]
            model_name = route.response_schema.name if route.response_schema else "ResponseModel"
            findings.append(Finding(
                id=fid,
                rule_id=rule,
                title="Response payload missing expected field",
                severity="high",
                confidence=0.90,
                category="Response Schema",
                message=f"Frontend expects response field '{full_name}' ({fe_field.type_name}) from {call.method} {call.path}, but backend model '{model_name}' does not provide it.",
                recommendation=f"Add field '{fe_name}' to backend response model '{model_name}', or mark it optional in frontend response type.",
                evidence=[fe_ev, be_ev],
                details={
                    "field": full_name,
                    "frontend_type": fe_field.type_name,
                    "backend_model": model_name,
                    "method": call.method,
                    "path": call.path,
                    "normalized_path": _normalise(call.path),
                },
            ))

    # 2. Check fields present in both for type compatibility and nullability
    for field_name, fe_field in fe_fields.items():
        be_field = None
        if field_name in be_fields:
            be_field = be_fields[field_name]
        else:
            for bf in be_fields.values():
                if getattr(bf, "alias", None) == field_name:
                    be_field = bf
                    break
        if not be_field:
            continue
        full_name = f"{prefix}{field_name}"

        fe_ev = Evidence(
            role="frontend",
            file=fe_field.file or call.file,
            line=fe_field.line or call.line,
            source=fe_field.source or call.source,
        )
        be_ev = Evidence(
            role="backend",
            file=be_field.file or route.file,
            line=be_field.line or route.line,
            source=be_field.source or route.source,
        )

        # Check nested schemas
        if fe_field.nested_fields and be_field.nested_fields:
            nested_findings = _compare_response_fields(
                fe_field.nested_fields,
                be_field.nested_fields,
                call,
                route,
                prefix=f"{full_name}.",
            )
            findings.extend(nested_findings)
            continue

        is_compat, reason = are_types_compatible(fe_field.type_name, be_field.type_name)
        if not is_compat:
            rule = "API008"
            fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{full_name}".encode()).hexdigest()[:12]
            ts_suggestion = map_py_to_ts(be_field.type_name)
            model_name = route.response_schema.name if route.response_schema else "ResponseModel"
            findings.append(Finding(
                id=fid,
                rule_id=rule,
                title="Response payload field type mismatch",
                severity="high",
                confidence=0.90,
                category="Response Schema",
                message=f"Response field '{full_name}' type mismatch on {call.method} {call.path}: frontend expects '{fe_field.type_name}', but backend model '{model_name}' returns '{be_field.type_name}'.",
                recommendation=f"Update frontend response type to expect '{ts_suggestion}', or update backend model '{model_name}'.",
                evidence=[fe_ev, be_ev],
                details={
                    "field": full_name,
                    "frontend_type": fe_field.type_name,
                    "backend_type": be_field.type_name,
                    "method": call.method,
                    "path": call.path,
                    "normalized_path": _normalise(call.path),
                },
            ))
        else:
            # Nullability check: backend field can be None, but frontend assumes it is non-null
            be_info = parse_type_info(be_field.type_name)
            fe_info = parse_type_info(fe_field.type_name)
            if be_info.get("nullable") and not fe_info.get("nullable") and fe_field.is_required:
                rule = "API009"
                fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{full_name}:res_null".encode()).hexdigest()[:12]
                findings.append(Finding(
                    id=fid,
                    rule_id=rule,
                    title="Response payload nullability mismatch",
                    severity="medium",
                    confidence=0.85,
                    category="Schema Nullability",
                    message=f"Response field '{full_name}' can be null/omitted in backend model '{route.response_schema.name if route.response_schema else 'ResponseModel'}', but frontend expects non-nullable '{fe_field.type_name}'. Unhandled null values may cause runtime errors.",
                    recommendation=f"Update frontend response field to allow null or undefined ('{field_name}?: {fe_field.type_name} | null').",
                    evidence=[fe_ev, be_ev],
                    details={
                        "field": full_name,
                        "backend_nullable": True,
                        "frontend_nullable": False,
                        "method": call.method,
                        "path": call.path,
                        "normalized_path": _normalise(call.path),
                    },
                ))

    return findings


def analyze(calls: list[ApiCall], routes: list[ApiRoute]) -> list[Finding]:
    """Perform cross-layer API contract analysis across frontend calls and backend routes."""
    findings: list[Finding] = []

    # 1. Rule API010: Check for duplicate backend routes
    route_groups: dict[tuple[str, str], list[ApiRoute]] = {}
    for route in routes:
        route_groups.setdefault((route.method, _normalise(route.path)), []).append(route)

    for (method, norm_path), group in route_groups.items():
        if len(group) > 1:
            rule = "API010"
            fid = hashlib.sha1(f"{rule}:{method}:{norm_path}".encode()).hexdigest()[:12]
            evidences = [Evidence(role="backend", file=r.file, line=r.line, source=r.source) for r in group]
            findings.append(Finding(
                id=fid,
                rule_id=rule,
                title="Duplicate backend route declaration",
                severity="medium",
                confidence=0.95,
                category="Backend Route Integrity",
                message=f"Backend declares {len(group)} duplicate route handlers for {method} {norm_path}.",
                recommendation="Remove or consolidate duplicate route declarations to prevent unexpected routing behavior.",
                evidence=evidences,
                details={"method": method, "normalized_path": norm_path, "count": len(group)},
            ))

    # 2. Check each frontend call against backend routes
    for call in calls:
        if getattr(call, "is_dynamic", False) or call.path == "<unresolved>" or not call.path.startswith("/") or "${" in call.path:
            continue
        key = (call.method, _normalise(call.path))
        matches = route_groups.get(key, [])
        call_evidence = Evidence(role="frontend", file=call.file, line=call.line, source=call.source)

        if not matches:
            same_path = [r for r in routes if _normalise(r.path) == _normalise(call.path)]
            if same_path:
                methods = ", ".join(sorted({r.method for r in same_path}))
                title = "HTTP method mismatch"
                rule = "API002"
                message = f"Frontend calls {call.method} {call.path}, but the backend declares this path with method(s): {methods}."
                recommendation = "Align the frontend HTTP method with the backend route, or add the intended backend method."
                severity = "high"
                evidence = [call_evidence] + [Evidence(role="backend", file=r.file, line=r.line, source=r.source) for r in same_path]
                conf = 0.94
                cat = "Routing"
                fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{call.method}:{_normalise(call.path)}".encode()).hexdigest()[:12]
                findings.append(Finding(
                    id=fid,
                    rule_id=rule,
                    title=title,
                    severity=severity,
                    confidence=conf,
                    category=cat,
                    message=message,
                    recommendation=recommendation,
                    evidence=evidence,
                    details={
                        "frontend_method": call.method,
                        "backend_methods": sorted({r.method for r in same_path}),
                        "path": call.path,
                        "normalized_path": _normalise(call.path),
                    },
                ))
            else:
                drift_match = _find_prefix_drift_match(call, routes)
                if drift_match:
                    route, prefix, direction = drift_match
                    rule = "INT001"
                    title = "API base path prefix drift"
                    severity = "high"
                    conf = 0.90
                    cat = "Integration"
                    if direction == "frontend_has_prefix":
                        message = (
                            f"Frontend calls {call.method} '{call.path}', but matching backend route is declared at "
                            f"'{route.path}' without base prefix '{prefix}'."
                        )
                    else:
                        message = (
                            f"Frontend calls {call.method} '{call.path}', but matching backend route is declared at "
                            f"'{route.path}' with base prefix '{prefix}'."
                        )
                    recommendation = (
                        f"Align the frontend request path or backend router mount prefix so that base prefix '{prefix}' "
                        f"is consistent across both layers."
                    )
                    evidence = [
                        call_evidence,
                        Evidence(role="backend", file=route.file, line=route.line, source=route.source),
                    ]
                    fid = hashlib.sha1(
                        f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(call.path)}:{_normalise(route.path)}".encode()
                    ).hexdigest()[:12]
                    findings.append(Finding(
                        id=fid,
                        rule_id=rule,
                        title=title,
                        severity=severity,
                        confidence=conf,
                        category=cat,
                        message=message,
                        recommendation=recommendation,
                        evidence=evidence,
                        details={
                            "frontend_method": call.method,
                            "frontend_path": call.path,
                            "backend_path": route.path,
                            "prefix": prefix,
                            "direction": direction,
                            "normalized_frontend_path": _normalise(call.path),
                            "normalized_backend_path": _normalise(route.path),
                        },
                    ))
                else:
                    title = "No matching backend route"
                    rule = "API001"
                    message = f"No backend route was found for {call.method} {call.path}."
                    recommendation = "Confirm the URL and method, account for any router prefix, or implement the missing backend endpoint."
                    severity = "high"
                    evidence = [call_evidence]
                    conf = 0.86
                    cat = "Routing"
                    fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{call.method}:{_normalise(call.path)}".encode()).hexdigest()[:12]
                    findings.append(Finding(
                        id=fid,
                        rule_id=rule,
                        title=title,
                        severity=severity,
                        confidence=conf,
                        category=cat,
                        message=message,
                        recommendation=recommendation,
                        evidence=evidence,
                        details={
                            "frontend_method": call.method,
                            "path": call.path,
                            "normalized_path": _normalise(call.path),
                        },
                    ))
            continue

        for route in matches:
            route_evidence = Evidence(role="backend", file=route.file, line=route.line, source=route.source)
            frontend_params = re.findall(r"\{([^{}]+)\}", call.path)
            backend_params = route.path_params

            # Rule API003: Path parameter name mismatch
            if frontend_params and backend_params and frontend_params != backend_params:
                fid = hashlib.sha1(f"API003:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(route.path)}".encode()).hexdigest()[:12]
                findings.append(Finding(
                    id=fid,
                    rule_id="API003",
                    title="Path parameter name mismatch",
                    severity="medium",
                    confidence=0.82,
                    category="Path Parameters",
                    message=f"The frontend uses path parameter(s) {frontend_params}, while the backend declares {backend_params}. The route shape matches, but parameter binding may fail.",
                    recommendation="Use consistent parameter names across the frontend and backend, then verify the final URL produced at runtime.",
                    evidence=[call_evidence, route_evidence],
                    details={
                        "frontend_params": frontend_params,
                        "backend_params": backend_params,
                        "method": call.method,
                        "path": call.path,
                        "normalized_path": _normalise(route.path),
                    },
                ))

            # Rule API004: Path parameter type mismatch
            for i, p_name in enumerate(frontend_params):
                fe_type = call.path_param_types.get(p_name)
                # Find corresponding backend param (either same name or position)
                be_name = p_name if p_name in route.path_param_types else (backend_params[i] if i < len(backend_params) else None)
                be_type = route.path_param_types.get(be_name) if be_name else None

                if fe_type and be_type:
                    is_compat, reason = are_types_compatible(fe_type, be_type)
                    if not is_compat:
                        rule = "API004"
                        # Stable identity keyed on normalized route and parameter slot index / backend param
                        param_slot_key = be_name or f"param_{i}"
                        fid = hashlib.sha1(f"{rule}:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(route.path)}:{param_slot_key}".encode()).hexdigest()[:12]
                        ts_suggestion = map_py_to_ts(be_type)
                        findings.append(Finding(
                            id=fid,
                            rule_id=rule,
                            title="Path parameter type mismatch",
                            severity="high",
                            confidence=0.88,
                            category="Path Parameters",
                            message=f"Path parameter '{p_name}' type mismatch on {call.method} {call.path}: frontend passes '{fe_type}', but backend expects '{be_type}'.",
                            recommendation=f"Update parameter '{p_name}' in frontend to '{ts_suggestion}', or update backend parameter '{be_name}' to '{fe_type}'.",
                            evidence=[call_evidence, route_evidence],
                            details={
                                "parameter": p_name,
                                "backend_param": be_name,
                                "param_index": i,
                                "frontend_type": fe_type,
                                "backend_type": be_type,
                                "method": call.method,
                                "path": call.path,
                                "normalized_path": _normalise(route.path),
                            },
                        ))

            # Rule API005, API006, API009: Request payload schema comparison
            if call.request_schema and route.request_schema:
                req_findings = _compare_request_fields(
                    call.request_schema.fields,
                    route.request_schema.fields,
                    call,
                    route,
                )
                findings.extend(req_findings)

            # Rule API007, API008, API009: Response payload schema comparison
            if call.response_schema and route.response_schema:
                res_findings = _compare_response_fields(
                    call.response_schema.fields,
                    route.response_schema.fields,
                    call,
                    route,
                )
                findings.extend(res_findings)

            # Rule API011: Required Query Parameter Missing in Frontend Call
            if route.required_query_params:
                call_query_str = call.path.split("?")[1] if "?" in call.path else ""
                call_queries = {p.split("=")[0] for p in call_query_str.split("&") if p}
                call_src = call.source
                for req_q in route.required_query_params:
                    found_in_src = (
                        f"?{req_q}=" in call_src
                        or f"&{req_q}=" in call_src
                        or f"?{req_q}" in call_src
                        or f"'{req_q}'" in call_src
                        or f'"{req_q}"' in call_src
                        or f"{req_q}:" in call_src
                    )
                    if not (req_q in call_queries or found_in_src):
                        fid = hashlib.sha1(f"API011:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(route.path)}:{req_q}".encode()).hexdigest()[:12]
                        findings.append(Finding(
                            id=fid,
                            rule_id="API011",
                            title=f"Missing required query parameter '{req_q}'",
                            severity="medium",
                            confidence=0.88,
                            category="Query Parameters",
                            message=f"Frontend calls {call.method} {call.path} without required query parameter '{req_q}' expected by backend route {route.path}.",
                            recommendation=f"Include '{req_q}' in the query string: e.g. '{call.path}?{req_q}=...'.",
                            evidence=[call_evidence, route_evidence],
                            details={"query_param": req_q, "method": call.method, "path": call.path},
                        ))

            # Rule API012: Missing Authentication Header in Secured Endpoint Call
            if route.is_authenticated:
                call_src = call.source.lower()
                has_auth = getattr(call, "has_auth_header", False) or any(k in call_src for k in ("auth", "token", "bearer", "authorization", "credential"))
                if not has_auth:
                    fid = hashlib.sha1(f"API012:{_normalise_file(call.file)}:{_normalise_file(route.file)}:{call.method}:{_normalise(route.path)}".encode()).hexdigest()[:12]
                    findings.append(Finding(
                        id=fid,
                        rule_id="API012",
                        title="Secured backend endpoint called without authentication header",
                        severity="high",
                        confidence=0.88,
                        category="Authentication",
                        message=f"Backend endpoint {call.method} {route.path} requires authentication, but frontend call passes no Authorization header or authentication credentials.",
                        recommendation="Pass an Authorization header (e.g. 'Bearer <token>') or include auth credentials in the request options.",
                        evidence=[call_evidence, route_evidence],
                        details={"method": call.method, "path": call.path, "route_file": route.file},
                    ))

    return findings


def _relative_to_root(path_str: str, root: Path) -> str:
    try:
        p = Path(path_str)
        if not p.is_absolute():
            # Already relative
            return path_str.replace("\\", "/")
        p = p.resolve()
        r = root.resolve()
        p_str = str(p).lower()
        r_str = str(r).lower()
        if p_str.startswith(r_str):
            rel = str(p)[len(str(r)):].lstrip("\\/")
            return rel.replace("\\", "/")
        return str(p.relative_to(r)).replace("\\", "/")
    except Exception:
        return Path(path_str).name


def _check_websocket_integration(frontend_root: Path, routes: list[ApiRoute]) -> list[Finding]:
    """Detect unmatched WebSocket endpoints between frontend client and backend routes (INT002)."""
    findings: list[Finding] = []
    if not frontend_root.exists():
        return findings

    ws_routes = {_normalise(r.path) for r in routes if r.method == "WEBSOCKET"}
    ws_pattern = re.compile(r"""\b(?:new\s+WebSocket|useWebSocket)\s*\(\s*['"`]([^\r\n'"`]+)['"`]""")

    import os
    for dirpath, dirnames, filenames in os.walk(frontend_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "dist", "build"}]
        for fname in filenames:
            if fname.endswith((".ts", ".tsx", ".js", ".jsx")):
                file_path = Path(dirpath) / fname
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                lines = content.splitlines()
                for m in ws_pattern.finditer(content):
                    raw_url = m.group(1).strip()
                    if not raw_url or "${" in raw_url:
                        continue
                    # Extract path from URL (e.g. ws://localhost:8000/ws/feed -> /ws/feed)
                    path_part = re.sub(r"^wss?://[^/]+", "", raw_url)
                    if not path_part.startswith("/"):
                        path_part = "/" + path_part
                    norm_path = _normalise(path_part)
                    if norm_path not in ws_routes:
                        lineno = content.count("\n", 0, m.start()) + 1
                        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"new WebSocket('{raw_url}')"
                        fid = hashlib.sha1(f"INT002:{_normalise_file(str(file_path))}:{lineno}:{norm_path}".encode()).hexdigest()[:12]
                        findings.append(Finding(
                            id=fid,
                            rule_id="INT002",
                            title=f"Unmatched WebSocket endpoint '{norm_path}'",
                            severity="high",
                            confidence=0.88,
                            category="Integration",
                            message=f"Frontend initiates WebSocket connection to '{raw_url}', but no backend route declares @app.websocket('{norm_path}').",
                            recommendation=f"Implement a WebSocket handler at '{norm_path}' on the backend, or align the frontend connection URL.",
                            evidence=[Evidence(role="frontend", file=str(file_path), line=lineno, source=snippet)],
                            details={"raw_url": raw_url, "normalized_path": norm_path},
                        ))
    return findings


def scan_project(
    project_path: str,
    openapi_path: str | None = None,
    auto_detect_openapi: bool = True,
    allowed_roots: list[Path] | None = None,
) -> dict:
    """Scan a local project directory and optionally validate against an OpenAPI specification."""
    root = Path(project_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {root}")

    from .monorepo import discover_monorepo
    mono = discover_monorepo(root)

    # Monorepo layout discovery with root fallback
    candidates_fe = [
        root / "frontend" / "src",
        root / "frontend",
        root / "client" / "src",
        root / "client",
        root / "web" / "src",
        root / "web",
        root / "ui" / "src",
        root / "ui",
        root / "apps" / "web",
        root / "apps" / "client",
        root / "packages" / "frontend",
        root / "packages" / "client",
    ]
    if (root / "src").is_dir() and any((root / d).is_dir() for d in ("server", "backend", "api")):
        candidates_fe.insert(0, root / "src")

    fallback_fe = root
    for cand in candidates_fe:
        if cand.is_dir():
            fallback_fe = cand
            break

    candidates_be = [
        root / "backend",
        root / "server",
        root / "api",
        root / "services",
        root / "apps" / "api",
        root / "apps" / "server",
        root / "packages" / "backend",
        root / "packages" / "server",
    ]
    fallback_be = root
    for cand in candidates_be:
        if cand.is_dir():
            fallback_be = cand
            break

    fe_roots = list(dict.fromkeys(p.resolve() for p in (mono.frontend_roots if mono.frontend_roots else [fallback_fe])))
    be_roots = list(dict.fromkeys(p.resolve() for p in (mono.backend_roots if mono.backend_roots else [fallback_be])))
    sh_roots = list(dict.fromkeys(p.resolve() for p in mono.shared_roots))

    from .frontend import extract_frontend_models, extract_frontend_calls
    from .backend import extract_backend_models, extract_backend_routes
    from .graph import build_dependency_graph
    from .root_cause import analyze_root_causes
    from .models import OpenApiSpecInfo
    from .openapi import (
        find_conventional_spec,
        safe_load_spec,
        extract_openapi_operations,
        cross_validate_openapi,
    )
    from .repair import validate_safe_path

    fe_models: dict[str, SchemaModel] = {}
    for r_dir in list(dict.fromkeys(sh_roots + fe_roots)):
        fe_models.update(extract_frontend_models(r_dir))

    be_models: dict[str, SchemaModel] = {}
    for r_dir in list(dict.fromkeys(sh_roots + be_roots)):
        be_models.update(extract_backend_models(r_dir))

    raw_calls: list[ApiCall] = []
    for f_dir in fe_roots:
        raw_calls.extend(extract_frontend_calls(f_dir, fe_models))

    # De-duplicate calls extracted from overlapping roots
    seen_call_keys: set[tuple[str, str, str, int]] = set()
    calls: list[ApiCall] = []
    for c in raw_calls:
        ckey = (c.method, c.path, c.file, c.line)
        if ckey not in seen_call_keys:
            seen_call_keys.add(ckey)
            calls.append(c)

    raw_routes: list[ApiRoute] = []
    for b_dir in be_roots:
        raw_routes.extend(extract_backend_routes(b_dir, be_models))

    # De-duplicate routes extracted from overlapping roots
    seen_route_keys: set[tuple[str, str, str, int]] = set()
    routes: list[ApiRoute] = []
    for r in raw_routes:
        rkey = (r.method, r.path, r.file, r.line)
        if rkey not in seen_route_keys:
            seen_route_keys.add(rkey)
            routes.append(r)

    findings = analyze(calls, routes)

    # Configuration analysis (CFG001, CFG002)
    from .config_analyzer import analyze_config as _analyze_config
    findings = findings + _analyze_config(root)

    # Frontend static diagnostics (FE001)
    from .frontend_diagnostics import analyze_frontend_diagnostics as _analyze_frontend
    findings = findings + _analyze_frontend(root)

    # Backend static diagnostics (BE001)
    from .backend_diagnostics import analyze_backend_diagnostics as _analyze_backend
    findings = findings + _analyze_backend(root)

    # WebSocket Integration diagnostics (INT002)
    for f_dir in fe_roots:
        findings = findings + _check_websocket_integration(f_dir, routes)

    # Build & Dependency diagnostics (BLD001, BLD002, BLD003)
    from .build_diagnostics import analyze_build_diagnostics as _analyze_build
    findings = findings + _analyze_build(root)

    # Database schema diagnostics (DB001-DB007)
    from .db_diagnostics import analyze_database_diagnostics as _analyze_db
    findings = findings + _analyze_db(root)

    # Optional OpenAPI Discovery & Cross-Validation
    spec_file: Path | None = None
    if openapi_path:
        cand = Path(openapi_path).expanduser()
        try:
            spec_file = validate_safe_path(cand, root, allowed_roots)
        except ValueError as exc:
            raise ValueError(f"Invalid OpenAPI specification path: {exc}") from exc
        if not spec_file.is_file():
            raise ValueError(f"Specified OpenAPI file does not exist: {openapi_path}")
    elif auto_detect_openapi:
        spec_file = find_conventional_spec(root)

    scan_mode = "static_only"
    spec_info_dict: dict | None = None
    disagreements_list: list[dict] = []

    if spec_file is not None:
        doc, fmt, spec_ver = safe_load_spec(spec_file)
        info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
        spec_title = str(info.get("title", "OpenAPI Specification"))
        spec_app_ver = str(info.get("version", "1.0.0"))
        rel_spec_path = _relative_to_root(str(spec_file), root)

        spec_info = OpenApiSpecInfo(
            title=spec_title,
            version=spec_app_ver,
            spec_version=spec_ver,
            path=rel_spec_path,
        )
        operations = extract_openapi_operations(doc, rel_spec_path)
        spec_info.operations_count = len(operations)

        disagreements = cross_validate_openapi(
            calls=calls,
            routes=routes,
            operations=operations,
            spec_info=spec_info,
            existing_finding_ids={f.id for f in findings},
        )
        scan_mode = "static_and_openapi"
        spec_info_dict = spec_info.model_dump()
        disagreements_list = [d.model_dump() for d in disagreements]

    # Discover relationships and root causes among findings
    finding_relationships, root_causes = analyze_root_causes(
        findings=findings,
        calls=calls,
        routes=routes,
        root_path=root,
    )

    # Build dependency graph linking calls, routes, schemas, findings, and root causes
    graph = build_dependency_graph(
        calls=calls,
        routes=routes,
        fe_models=fe_models,
        be_models=be_models,
        findings=findings,
        root_path=root,
        root_causes=root_causes,
    )

    # Convert evidence paths to project-relative paths, making copies to avoid shared mutation
    formatted_findings = []
    for finding in findings:
        updated_evidence = []
        for ev in finding.evidence:
            updated_evidence.append(Evidence(
                role=ev.role,
                file=_relative_to_root(ev.file, root),
                line=ev.line,
                source=ev.source,
            ))
        finding_dict = finding.model_dump()
        finding_dict["evidence"] = [e.model_dump() for e in updated_evidence]
        formatted_findings.append(finding_dict)

    return {
        "project_path": str(root),
        "scan_mode": scan_mode,
        "openapi_info": spec_info_dict,
        "openapi_disagreements": disagreements_list,
        "frontend_calls": len(calls),
        "backend_routes": len(routes),
        "findings": formatted_findings,
        "root_causes": [rc.model_dump() for rc in root_causes],
        "finding_relationships": [fr.model_dump() for fr in finding_relationships],
        "graph": graph.model_dump(),
        "monorepo_structure": mono.to_dict(),
    }
