from __future__ import annotations
import re
from pathlib import Path
from typing import Any
from .models import (
    ApiCall,
    ApiRoute,
    DependencyGraph,
    Finding,
    GraphEdge,
    GraphNode,
    SchemaModel,
)
from .root_cause_models import RootCauseCandidate


def _normalise(path: str) -> str:
    return re.sub(r"\{[^{}]+\}", "{}", path).rstrip("/") or "/"


def _to_rel_path(path_str: str, root: Path | None) -> str:
    if not root:
        return path_str.replace("\\", "/")
    try:
        p = Path(path_str)
        if not p.is_absolute():
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


def build_dependency_graph(
    calls: list[ApiCall],
    routes: list[ApiRoute],
    fe_models: dict[str, SchemaModel],
    be_models: dict[str, SchemaModel],
    findings: list[Finding],
    root_path: str | Path | None = None,
    root_causes: list[RootCauseCandidate] | None = None,
) -> DependencyGraph:
    """Build a stable, verified dependency graph linking calls, routes, schemas, and findings."""
    root = Path(root_path).resolve() if root_path else None
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    node_id_set: set[str] = set()
    edge_id_set: set[str] = set()

    def add_node(node: GraphNode):
        if node.id not in node_id_set:
            node_id_set.add(node.id)
            nodes.append(node)

    def add_edge(edge: GraphEdge):
        if edge.id not in edge_id_set and edge.source in node_id_set and edge.target in node_id_set:
            edge_id_set.add(edge.id)
            edges.append(edge)

    # Maps to locate node IDs
    call_node_map: dict[tuple[str, int, str, str], str] = {}
    route_node_map: dict[tuple[str, int, str, str], str] = {}
    fe_schema_node_map: dict[str, str] = {}
    be_schema_node_map: dict[str, str] = {}

    # 1. Frontend Call Nodes
    y_call = 60.0
    for call in calls:
        rel_file = _to_rel_path(call.file, root)
        node_id = f"call:{rel_file}:{call.line}:{call.method}:{call.path}"
        call_node_map[(call.file, call.line, call.method, call.path)] = node_id
        # Also index with relative file for flexible lookup
        call_node_map[(rel_file, call.line, call.method, call.path)] = node_id

        add_node(GraphNode(
            id=node_id,
            type="frontend_call",
            label=f"{call.method} {call.path}",
            sublabel=f"{rel_file}:{call.line}",
            file=rel_file,
            line=call.line,
            source=call.source,
            role="frontend",
            metadata={
                "method": call.method,
                "path": call.path,
                "request_type": call.request_type,
                "response_type": call.response_type,
                "path_param_types": call.path_param_types,
                "raw_path_params": call.raw_path_params,
            },
            position={"x": 50.0, "y": y_call},
        ))
        y_call += 140.0

    # 2. Frontend Schema Nodes
    y_fe_schema = 60.0
    for name, model in fe_models.items():
        rel_file = _to_rel_path(model.file, root)
        node_id = f"schema:fe:{name}:{rel_file}:{model.line}"
        fe_schema_node_map[name] = node_id

        add_node(GraphNode(
            id=node_id,
            type="schema_model",
            label=name,
            sublabel=f"TypeScript ({len(model.fields)} fields)",
            file=rel_file,
            line=model.line,
            source=model.source,
            role="frontend",
            metadata={
                "kind": "typescript_interface",
                "fields": {fn: f.model_dump() for fn, f in model.fields.items()},
            },
            position={"x": 360.0, "y": y_fe_schema},
        ))
        y_fe_schema += 140.0

    # 3. Backend Schema Nodes
    y_be_schema = 60.0
    for name, model in be_models.items():
        rel_file = _to_rel_path(model.file, root)
        node_id = f"schema:be:{name}:{rel_file}:{model.line}"
        be_schema_node_map[name] = node_id

        add_node(GraphNode(
            id=node_id,
            type="schema_model",
            label=name,
            sublabel=f"Pydantic ({len(model.fields)} fields)",
            file=rel_file,
            line=model.line,
            source=model.source,
            role="backend",
            metadata={
                "kind": "pydantic_model",
                "fields": {fn: f.model_dump() for fn, f in model.fields.items()},
            },
            position={"x": 680.0, "y": y_be_schema},
        ))
        y_be_schema += 140.0

    # 4. Backend Route Nodes
    y_route = 60.0
    for route in routes:
        rel_file = _to_rel_path(route.file, root)
        node_id = f"route:{rel_file}:{route.line}:{route.method}:{route.path}"
        route_node_map[(route.file, route.line, route.method, route.path)] = node_id
        route_node_map[(rel_file, route.line, route.method, route.path)] = node_id

        add_node(GraphNode(
            id=node_id,
            type="backend_route",
            label=f"{route.method} {route.path}",
            sublabel=f"{rel_file}:{route.line}",
            file=rel_file,
            line=route.line,
            source=route.source,
            role="backend",
            metadata={
                "method": route.method,
                "path": route.path,
                "request_model": route.request_model,
                "response_model": route.response_model,
                "path_params": route.path_params,
                "path_param_types": route.path_param_types,
            },
            position={"x": 1000.0, "y": y_route},
        ))
        y_route += 140.0

    # 5. Schema to Schema references (nested models)
    for model in fe_models.values():
        p_id = fe_schema_node_map.get(model.name)
        if not p_id:
            continue
        for field in model.fields.values():
            if field.nested_model and field.nested_model in fe_schema_node_map:
                c_id = fe_schema_node_map[field.nested_model]
                add_edge(GraphEdge(
                    id=f"edge:nested:{p_id}->{c_id}:{field.name}",
                    source=p_id,
                    target=c_id,
                    type="references_model",
                    label=f"field: {field.name}",
                ))

    for model in be_models.values():
        p_id = be_schema_node_map.get(model.name)
        if not p_id:
            continue
        for field in model.fields.values():
            if field.nested_model and field.nested_model in be_schema_node_map:
                c_id = be_schema_node_map[field.nested_model]
                add_edge(GraphEdge(
                    id=f"edge:nested:{p_id}->{c_id}:{field.name}",
                    source=p_id,
                    target=c_id,
                    type="references_model",
                    label=f"field: {field.name}",
                ))

    # 6. Call to Frontend Schema edges
    for call in calls:
        call_id = call_node_map.get((call.file, call.line, call.method, call.path))
        if not call_id:
            continue
        if call.request_type and call.request_type in fe_schema_node_map:
            s_id = fe_schema_node_map[call.request_type]
            add_edge(GraphEdge(
                id=f"edge:call_req:{call_id}->{s_id}",
                source=call_id,
                target=s_id,
                type="uses_request_schema",
                label="request payload",
            ))
        if call.response_type and call.response_type in fe_schema_node_map:
            s_id = fe_schema_node_map[call.response_type]
            add_edge(GraphEdge(
                id=f"edge:call_res:{call_id}->{s_id}",
                source=call_id,
                target=s_id,
                type="uses_response_schema",
                label="response payload",
            ))

    # 7. Route to Backend Schema edges
    for route in routes:
        route_id = route_node_map.get((route.file, route.line, route.method, route.path))
        if not route_id:
            continue
        if route.request_model and route.request_model in be_schema_node_map:
            s_id = be_schema_node_map[route.request_model]
            add_edge(GraphEdge(
                id=f"edge:route_req:{route_id}->{s_id}",
                source=route_id,
                target=s_id,
                type="uses_request_schema",
                label="request body",
            ))
        if route.response_model and route.response_model in be_schema_node_map:
            s_id = be_schema_node_map[route.response_model]
            add_edge(GraphEdge(
                id=f"edge:route_res:{route_id}->{s_id}",
                source=route_id,
                target=s_id,
                type="uses_response_schema",
                label="response model",
            ))

    # 7b. Schema to Component File edges (explicit evidence-backed declarations)
    x_schema_file = 360.0
    for name, model in fe_models.items():
        s_id = fe_schema_node_map.get(name)
        if not s_id:
            continue
        rel_file = _to_rel_path(model.file, root)
        file_node_id = f"component_file:{rel_file}"
        if file_node_id not in node_id_set:
            add_node(GraphNode(
                id=file_node_id,
                type="component_file",
                label=Path(rel_file).name or rel_file,
                sublabel=rel_file,
                file=rel_file,
                role="shared",
                metadata={"path": rel_file},
                position={"x": x_schema_file, "y": -70.0},
            ))
            x_schema_file += 280.0
        add_edge(GraphEdge(
            id=f"edge:schema_file:{s_id}->{file_node_id}",
            source=s_id,
            target=file_node_id,
            type="declared_in_file",
            label="declared in",
            is_mismatch=False,
        ))

    for name, model in be_models.items():
        s_id = be_schema_node_map.get(name)
        if not s_id:
            continue
        rel_file = _to_rel_path(model.file, root)
        file_node_id = f"component_file:{rel_file}"
        if file_node_id not in node_id_set:
            add_node(GraphNode(
                id=file_node_id,
                type="component_file",
                label=Path(rel_file).name or rel_file,
                sublabel=rel_file,
                file=rel_file,
                role="shared",
                metadata={"path": rel_file},
                position={"x": x_schema_file, "y": -70.0},
            ))
            x_schema_file += 280.0
        add_edge(GraphEdge(
            id=f"edge:schema_file:{s_id}->{file_node_id}",
            source=s_id,
            target=file_node_id,
            type="declared_in_file",
            label="declared in",
            is_mismatch=False,
        ))

    # 8. Call to Route edges (verified relationships only)
    route_norm_map: dict[tuple[str, str], list[ApiRoute]] = {}
    for route in routes:
        route_norm_map.setdefault((route.method, _normalise(route.path)), []).append(route)

    for call in calls:
        call_id = call_node_map.get((call.file, call.line, call.method, call.path))
        if not call_id:
            continue
        call_rel_file = _to_rel_path(call.file, root)
        matches = route_norm_map.get((call.method, _normalise(call.path)), [])
        for route in matches:
            r_id = route_node_map.get((route.file, route.line, route.method, route.path))
            if r_id:
                has_finding = any(
                    f.rule_id in {"API003", "API004", "API005", "API006", "API007", "API008", "API009"}
                    and any(
                        e.role == "frontend"
                        and e.line == call.line
                        and _to_rel_path(e.file, root) == call_rel_file
                        for e in f.evidence
                    )
                    for f in findings
                )
                add_edge(GraphEdge(
                    id=f"edge:call_route:{call_id}->{r_id}",
                    source=call_id,
                    target=r_id,
                    type="calls_route",
                    label=f"{call.method} {call.path}",
                    is_mismatch=has_finding,
                ))

        # Check for same path different method (API002)
        if not matches:
            same_path_routes = [r for r in routes if _normalise(r.path) == _normalise(call.path)]
            for spr in same_path_routes:
                r_id = route_node_map.get((spr.file, spr.line, spr.method, spr.path))
                if r_id:
                    add_edge(GraphEdge(
                        id=f"edge:call_route_mismatch:{call_id}->{r_id}",
                        source=call_id,
                        target=r_id,
                        type="calls_route",
                        label="method mismatch",
                        is_mismatch=True,
                    ))

            # Check for INT001 prefix drift
            int001_findings = [
                f for f in findings
                if f.rule_id == "INT001"
                and any(
                    e.role == "frontend"
                    and e.line == call.line
                    and _to_rel_path(e.file, root) == call_rel_file
                    for e in f.evidence
                )
            ]
            for f in int001_findings:
                be_ev = next((e for e in f.evidence if e.role == "backend"), None)
                if be_ev:
                    be_ev_rel = _to_rel_path(be_ev.file, root)
                    for r in routes:
                        if r.line == be_ev.line and _to_rel_path(r.file, root) == be_ev_rel:
                            r_id = route_node_map.get((r.file, r.line, r.method, r.path))
                            if r_id:
                                prefix = f.details.get("prefix", "") if f.details else ""
                                add_edge(GraphEdge(
                                    id=f"edge:call_route_prefix_drift:{call_id}->{r_id}",
                                    source=call_id,
                                    target=r_id,
                                    type="calls_route",
                                    label=f"prefix drift ({prefix})" if prefix else "prefix drift",
                                    is_mismatch=True,
                                ))

    # 9. Finding Nodes and Issue Edges
    y_finding = max(y_call, y_route, y_fe_schema, y_be_schema, 200.0) + 40.0
    x_finding = 50.0

    for idx, finding in enumerate(findings):
        f_node_id = f"finding:{finding.id}"
        finding.node_ids = [f_node_id]
        finding.edge_ids = []

        first_ev_file = _to_rel_path(finding.evidence[0].file, root) if finding.evidence else None

        add_node(GraphNode(
            id=f_node_id,
            type="finding",
            label=f"{finding.rule_id}: {finding.title}",
            sublabel=f"{finding.severity.upper()} severity • {int(finding.confidence * 100)}% conf",
            file=first_ev_file,
            line=finding.evidence[0].line if finding.evidence else None,
            source=finding.evidence[0].source if finding.evidence else None,
            severity=finding.severity,
            role="shared",
            metadata={
                "rule_id": finding.rule_id,
                "message": finding.message,
                "recommendation": finding.recommendation,
                "category": finding.category,
                "details": finding.details or {},
            },
            position={"x": x_finding, "y": y_finding},
        ))
        x_finding += 340.0
        if (idx + 1) % 3 == 0:
            x_finding = 50.0
            y_finding += 160.0

        # Link finding node to verified evidence nodes using strict provenance
        for ev in finding.evidence:
            ev_rel_file = _to_rel_path(ev.file, root)
            matched_node_id: str | None = None

            if ev.role == "frontend":
                file_calls = [c for c in calls if _to_rel_path(c.file, root) == ev_rel_file]
                # 1. Exact file and line match
                for c in file_calls:
                    if c.line == ev.line:
                        matched_node_id = call_node_map.get((c.file, c.line, c.method, c.path))
                        break

                # 2. Verified relationship metadata in finding details
                if not matched_node_id and finding.details and file_calls:
                    fe_method = (finding.details.get("frontend_method") or finding.details.get("method") or "").upper()
                    fe_path = finding.details.get("frontend_path") or finding.details.get("path") or ""
                    if fe_method and fe_path:
                        for c in file_calls:
                            if c.method.upper() == fe_method and (_normalise(c.path) == _normalise(fe_path) or c.path == fe_path):
                                matched_node_id = call_node_map.get((c.file, c.line, c.method, c.path))
                                break

                # 3. Check frontend schemas in same file
                if not matched_node_id:
                    for sname, snid in fe_schema_node_map.items():
                        m = fe_models.get(sname)
                        if m and _to_rel_path(m.file, root) == ev_rel_file:
                            if m.line == ev.line or any(f.line == ev.line for f in m.fields.values()):
                                matched_node_id = snid
                                break
                            if finding.details and (
                                finding.details.get("model") == sname
                                or finding.details.get("request_type") == sname
                                or finding.details.get("response_type") == sname
                            ):
                                matched_node_id = snid
                                break

            elif ev.role == "backend":
                file_routes = [r for r in routes if _to_rel_path(r.file, root) == ev_rel_file]
                # 1. Exact file and line match
                for r in file_routes:
                    if r.line == ev.line:
                        matched_node_id = route_node_map.get((r.file, r.line, r.method, r.path))
                        break

                # 2. Verified relationship metadata in finding details
                if not matched_node_id and finding.details and file_routes:
                    be_method = (finding.details.get("method") or finding.details.get("frontend_method") or "").upper()
                    be_path = finding.details.get("backend_path") or finding.details.get("path") or ""
                    if be_method and be_path:
                        for r in file_routes:
                            if r.method.upper() == be_method and (_normalise(r.path) == _normalise(be_path) or r.path == be_path):
                                matched_node_id = route_node_map.get((r.file, r.line, r.method, r.path))
                                break

                # 3. Check backend schemas in same file
                if not matched_node_id:
                    for sname, snid in be_schema_node_map.items():
                        m = be_models.get(sname)
                        if m and _to_rel_path(m.file, root) == ev_rel_file:
                            if m.line == ev.line or any(f.line == ev.line for f in m.fields.values()):
                                matched_node_id = snid
                                break
                            if finding.details and (
                                finding.details.get("model") == sname
                                or finding.details.get("request_model") == sname
                                or finding.details.get("response_model") == sname
                            ):
                                matched_node_id = snid
                                break

            if matched_node_id and matched_node_id in node_id_set:
                edge_id = f"edge:finding:{f_node_id}->{matched_node_id}"
                add_edge(GraphEdge(
                    id=edge_id,
                    source=f_node_id,
                    target=matched_node_id,
                    type="flags_issue",
                    label=finding.rule_id,
                    is_mismatch=True,
                ))
                if matched_node_id not in finding.node_ids:
                    finding.node_ids.append(matched_node_id)
                if edge_id not in finding.edge_ids:
                    finding.edge_ids.append(edge_id)

    # 10. Root Cause Nodes & Multi-Hop Edges
    if root_causes:
        x_rc = 80.0
        y_rc = -180.0
        x_file = 80.0
        y_file = -70.0

        finding_map = {f.id: f for f in findings}

        for rc_idx, rc in enumerate(root_causes):
            rc_node_id = f"root_cause:{rc.id}"
            rc.node_ids = [rc_node_id]
            rc.edge_ids = []

            first_comp = _to_rel_path(rc.affected_components[0], root) if rc.affected_components else None

            add_node(GraphNode(
                id=rc_node_id,
                type="root_cause",
                label=rc.title,
                sublabel=f"{rc.state} • {int(rc.confidence * 100)}% conf • {len(rc.finding_ids)} issues",
                file=first_comp,
                role="shared",
                severity=rc.severity,
                metadata={
                    "root_cause_id": rc.id,
                    "category": rc.category,
                    "state": rc.state,
                    "confidence": rc.confidence,
                    "description": rc.description,
                    "recommended_action": rc.recommended_action,
                    "finding_ids": rc.finding_ids,
                    "affected_components": [_to_rel_path(c, root) for c in rc.affected_components],
                    "impact_summary": rc.impact_summary,
                    "shared_entity": rc.shared_entity,
                    "suggested_order": rc.suggested_order,
                },
                position={"x": x_rc, "y": y_rc},
            ))
            x_rc += 360.0
            if (rc_idx + 1) % 3 == 0:
                x_rc = 80.0
                y_rc -= 140.0

            # 10a. Edges from Root Cause to Findings
            for fid in rc.finding_ids:
                f_node_id = f"finding:{fid}"
                if f_node_id in node_id_set:
                    edge_id = f"edge:causes:{rc_node_id}->{f_node_id}"
                    add_edge(GraphEdge(
                        id=edge_id,
                        source=rc_node_id,
                        target=f_node_id,
                        type="causes_finding",
                        label="causes",
                        is_mismatch=True,
                    ))
                    if f_node_id not in rc.node_ids:
                        rc.node_ids.append(f_node_id)
                    if edge_id not in rc.edge_ids:
                        rc.edge_ids.append(edge_id)

                    f_obj = finding_map.get(fid)
                    if f_obj:
                        for nid in f_obj.node_ids:
                            if nid not in rc.node_ids:
                                rc.node_ids.append(nid)
                        for eid in f_obj.edge_ids:
                            if eid not in rc.edge_ids:
                                rc.edge_ids.append(eid)

            # 10b. Multi-hop provenance chain: Call/Route -> Schema -> Component File
            for nid in list(rc.node_ids):
                for e in edges:
                    if e.source == nid:
                        if e.type in ("uses_request_schema", "uses_response_schema"):
                            if e.target not in rc.node_ids:
                                rc.node_ids.append(e.target)
                            if e.id not in rc.edge_ids:
                                rc.edge_ids.append(e.id)
                            # Trace downstream schema declaration file
                            for e_sub in edges:
                                if e_sub.source == e.target and e_sub.type == "declared_in_file":
                                    if e_sub.target not in rc.node_ids:
                                        rc.node_ids.append(e_sub.target)
                                    if e_sub.id not in rc.edge_ids:
                                        rc.edge_ids.append(e_sub.id)
                        elif e.type == "declared_in_file":
                            if e.target not in rc.node_ids:
                                rc.node_ids.append(e.target)
                            if e.id not in rc.edge_ids:
                                rc.edge_ids.append(e.id)

            # 10c. Affected Component File Nodes and Edges
            for comp in rc.affected_components:
                comp_rel = _to_rel_path(comp, root)
                file_node_id = f"component_file:{comp_rel}"
                if file_node_id not in node_id_set:
                    add_node(GraphNode(
                        id=file_node_id,
                        type="component_file",
                        label=Path(comp_rel).name or comp_rel,
                        sublabel=comp_rel,
                        file=comp_rel,
                        role="shared",
                        metadata={"path": comp_rel},
                        position={"x": x_file, "y": y_file},
                    ))
                    x_file += 280.0

                edge_id = f"edge:affects:{rc_node_id}->{file_node_id}"
                add_edge(GraphEdge(
                    id=edge_id,
                    source=rc_node_id,
                    target=file_node_id,
                    type="affects_component",
                    label="affects",
                    is_mismatch=False,
                ))
                if file_node_id not in rc.node_ids:
                    rc.node_ids.append(file_node_id)
                if edge_id not in rc.edge_ids:
                    rc.edge_ids.append(edge_id)

    return DependencyGraph(nodes=nodes, edges=edges)
