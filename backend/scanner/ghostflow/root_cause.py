"""Root-Cause Intelligence Engine (Phase 4 / 4.1).

Discovers deterministic causal relationships between findings, synthesizes
root-cause candidates with explicit states (CONFIRMED, LIKELY, POSSIBLE),
traces affected components, and determines optimal investigation order.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .models import Finding, ApiCall, ApiRoute, Evidence, Severity
from .root_cause_models import (
    FindingRelationship,
    RootCauseCandidate,
    RelationshipState,
    RelationshipType,
)


def _normalise_rel_path(p: str, root: Path | None = None) -> str:
    cleaned = p.replace("\\", "/").strip()
    if root:
        try:
            rp = Path(cleaned)
            if rp.is_absolute():
                cleaned = str(rp.relative_to(root.resolve())).replace("\\", "/")
        except Exception:
            pass
    return cleaned


def analyze_root_causes(
    findings: list[Finding],
    calls: list[ApiCall],
    routes: list[ApiRoute],
    root_path: Path | None = None,
) -> tuple[list[FindingRelationship], list[RootCauseCandidate]]:
    """
    Analyze diagnostic findings and extract verified finding relationships and
    synthesized root-cause candidates with strict evidentiary states.
    """
    if not findings:
        return ([], [])

    relationships: list[FindingRelationship] = []
    candidates: list[RootCauseCandidate] = []
    seen_rel_pairs: set[tuple[str, str, str]] = set()

    def add_relationship(
        src_id: str,
        tgt_id: str,
        rel_type: RelationshipType,
        state: RelationshipState,
        conf: float,
        entity: str,
        files: list[str],
        expl: str,
    ):
        pair_key = (min(src_id, tgt_id), max(src_id, tgt_id), rel_type)
        if pair_key not in seen_rel_pairs:
            seen_rel_pairs.add(pair_key)
            relationships.append(FindingRelationship(
                source_finding_id=src_id,
                target_finding_id=tgt_id,
                relationship_type=rel_type,
                state=state,
                confidence=round(conf, 2),
                shared_entity=entity,
                related_files=sorted(set(_normalise_rel_path(f, root_path) for f in files if f)),
                explanation=expl,
            ))

    # Index findings by rule_id
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    # -------------------------------------------------------------------------
    # 1. Shared Missing Module (FE001, BE001) -> CONFIRMED
    # -------------------------------------------------------------------------
    missing_module_groups: dict[str, list[Finding]] = {}
    for rule_id in ("FE001", "BE001"):
        for f in by_rule.get(rule_id, []):
            module_name = None
            if f.details and "missing_import" in f.details:
                module_name = f.details["missing_import"]
            elif f.details and "target" in f.details:
                module_name = f.details["target"]
            else:
                m = re.search(r"import ['\"]([^'\"]+)['\"]", f.title) or re.search(r"import ['\"]([^'\"]+)['\"]", f.message)
                if m:
                    module_name = m.group(1)
            if module_name:
                missing_module_groups.setdefault(module_name, []).append(f)

    for mod_name, group in missing_module_groups.items():
        if len(group) >= 2:
            group_files = []
            for f in group:
                for ev in f.evidence:
                    if ev.file:
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_missing_module",
                        state="CONFIRMED",
                        conf=0.96,
                        entity=mod_name,
                        files=group_files,
                        expl=f"Both components attempt to import nonexistent module '{mod_name}'.",
                    )

            rc_id = f"rc_mod_{hashlib.sha1(mod_name.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=f"Shared Missing Module: '{mod_name}'",
                category="Dependencies & Modules",
                state="CONFIRMED",
                confidence=0.96,
                severity="high",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=f"Multiple components ({len(group_files)} files) fail to import '{mod_name}'. This missing local file or exported symbol cascades import resolution failures across these consumers.",
                recommended_action=f"Create '{mod_name}' at the required path or update import declarations in: {', '.join(group_files)}.",
                suggested_order=1,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"Causes {len(group)} import errors across {len(group_files)} files",
                shared_entity=mod_name,
            ))

    # -------------------------------------------------------------------------
    # 2. Shared Missing Dependency (BLD001, BLD002) -> CONFIRMED
    # -------------------------------------------------------------------------
    missing_dep_groups: dict[str, list[Finding]] = {}
    for rule_id in ("BLD001", "BLD002"):
        for f in by_rule.get(rule_id, []):
            pkg_name = None
            if f.details and "package" in f.details:
                pkg_name = f.details["package"]
            else:
                m = re.search(r"Missing dependency ['\"]([^'\"]+)['\"]", f.title) or re.search(r"package ['\"]([^'\"]+)['\"]", f.message)
                if m:
                    pkg_name = m.group(1)
            if pkg_name:
                missing_dep_groups.setdefault(pkg_name, []).append(f)

    for pkg_name, group in missing_dep_groups.items():
        if len(group) >= 2:
            group_files = []
            manifest = "package.json" if group[0].rule_id == "BLD001" else "requirements.txt"
            for f in group:
                for ev in f.evidence:
                    if ev.file and not ev.file.endswith(manifest):
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_missing_dependency",
                        state="CONFIRMED",
                        conf=0.98,
                        entity=pkg_name,
                        files=group_files,
                        expl=f"Multiple consumers depend on external package '{pkg_name}' which is undeclared in {manifest}.",
                    )

            rc_id = f"rc_dep_{hashlib.sha1(pkg_name.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=f"Undeclared Package Dependency: '{pkg_name}'",
                category="Build & Dependencies",
                state="CONFIRMED",
                confidence=0.98,
                severity="high",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=f"Package '{pkg_name}' is imported across {len(group_files)} files but omitted from project manifest ({manifest}). This breaks build compilation and packaging.",
                recommended_action=f"Add '{pkg_name}' to dependencies in {manifest} (e.g. npm install {pkg_name} or add to requirements.txt).",
                suggested_order=1,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"Blocks {len(group_files)} files importing '{pkg_name}'",
                shared_entity=pkg_name,
            ))

    # -------------------------------------------------------------------------
    # 3. Shared Prefix Drift (INT001, and related API001) -> LIKELY
    # -------------------------------------------------------------------------
    prefix_drift_findings = by_rule.get("INT001", [])
    if len(prefix_drift_findings) >= 2:
        prefix_groups: dict[str, list[Finding]] = {}
        for f in prefix_drift_findings:
            pfx = f.details.get("prefix", "common_prefix") if f.details else "common_prefix"
            prefix_groups.setdefault(pfx, []).append(f)

        for pfx, group in prefix_groups.items():
            group_files = []
            for f in group:
                for ev in f.evidence:
                    if ev.file:
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_prefix_drift",
                        state="LIKELY",
                        conf=0.92,
                        entity=pfx,
                        files=group_files,
                        expl=f"Systemic base path prefix drift pattern '{pfx}' detected across multiple endpoints.",
                    )

            rc_id = f"rc_pfx_{hashlib.sha1(pfx.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=f"Systemic API Base Path Prefix Drift ('{pfx}')",
                category="Integration",
                state="LIKELY",
                confidence=0.92,
                severity="high",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=f"Multiple endpoints ({len(group)}) exhibit prefix drift involving '{pfx}'. This indicates the frontend base URL or backend router mount path is systematically misaligned.",
                recommended_action=f"Configure the API client base URL or mount backend routers under consistent prefix '{pfx}'.",
                suggested_order=2,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"Causes {len(group)} routing mismatches across frontend and backend",
                shared_entity=pfx,
            ))

    # -------------------------------------------------------------------------
    # 4. Shared Endpoint Defect (Findings on the same route) -> CONFIRMED / LIKELY / POSSIBLE
    # -------------------------------------------------------------------------
    endpoint_groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if (f.rule_id.startswith("API") or f.rule_id == "INT001") and f.details:
            method = (f.details.get("method") or f.details.get("frontend_method") or "").upper()
            path = f.details.get("path") or f.details.get("normalized_path") or ""
            if method and path:
                endpoint_groups.setdefault((method, path), []).append(f)

    for (method, path), group in endpoint_groups.items():
        if len(group) >= 2:
            group_files = []
            for f in group:
                for ev in f.evidence:
                    if ev.file:
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            # Semantics audit: Determine if findings stem from shared cause vs independent defects
            # Group rules into concern dimensions:
            # - param_concern: API003, API004 (path parameters)
            # - payload_concern: API005, API006, API007, API008, API009 (request/response schemas)
            # - query_concern: API011 (query params)
            # - auth_concern: API012 (auth headers)
            # - routing_concern: API001, API002, INT001 (methods/routes)
            rule_set = {f.rule_id for f in group}
            is_same_param = (
                rule_set.issubset({"API003", "API004"})
                and len(set(f.details.get("param_name") or f.details.get("path_param") for f in group if f.details)) <= 1
            )
            is_same_payload = rule_set.issubset({"API005", "API006", "API007", "API008", "API009"})
            is_independent = (
                ("API012" in rule_set and len(rule_set - {"API012"}) > 0)
                or ("API011" in rule_set and len(rule_set - {"API011"}) > 0 and not is_same_param)
                or ("API002" in rule_set and "API004" in rule_set)
            )

            # Assign strict candidate and relationship state
            if is_same_param or is_same_payload:
                cand_state: RelationshipState = "CONFIRMED"
                cand_title = f"Compound Contract Desynchronization on {method} {path}"
                expl_text = f"Multiple contract defects ({', '.join(sorted(rule_set))}) on {method} {path} share an underlying parameter or schema specification defect."
            elif not is_independent:
                cand_state = "LIKELY"
                cand_title = f"Structural Endpoint Mismatches on {method} {path}"
                expl_text = f"Multiple contract defects ({', '.join(sorted(rule_set))}) co-occur on {method} {path}, likely indicating desynchronized client-server interfaces."
            else:
                cand_state = "POSSIBLE"
                cand_title = f"Co-Occurring Independent Defects on {method} {path}"
                expl_text = f"Independent defects ({', '.join(sorted(rule_set))}) occur on {method} {path} across orthogonal concerns (e.g. routing and authentication). These represent independent issues requiring separate remediation."

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_endpoint_defects",
                        state=cand_state,
                        conf=0.94 if cand_state == "CONFIRMED" else (0.88 if cand_state == "LIKELY" else 0.75),
                        entity=f"{method} {path}",
                        files=group_files,
                        expl=expl_text,
                    )

            rc_id = f"rc_ep_{hashlib.sha1(f'{method}:{path}'.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            rule_list_str = ", ".join(sorted(rule_set))
            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=cand_title,
                category="API Contracts",
                state=cand_state,
                confidence=0.94 if cand_state == "CONFIRMED" else (0.88 if cand_state == "LIKELY" else 0.75),
                severity="high" if any(f.severity == "high" for f in group) else "medium",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=expl_text,
                recommended_action=f"Inspect handler and caller for {method} {path} together to address {rule_list_str} systematically.",
                suggested_order=2 if cand_state == "CONFIRMED" else 3,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"Combines {len(group)} findings ({rule_list_str}) on {method} {path}",
                shared_entity=f"{method} {path}",
            ))

    # -------------------------------------------------------------------------
    # 5. Shared Schema Model (API005-API009, OAS004-OAS005) -> CONFIRMED
    # -------------------------------------------------------------------------
    schema_groups: dict[str, list[Finding]] = {}
    for f in findings:
        if f.rule_id in ("API005", "API006", "API007", "API008", "API009") and f.details:
            model_name = f.details.get("model") or f.details.get("schema")
            if model_name:
                schema_groups.setdefault(model_name, []).append(f)

    for model_name, group in schema_groups.items():
        if len(group) >= 2:
            group_files = []
            for f in group:
                for ev in f.evidence:
                    if ev.file:
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_schema_model",
                        state="CONFIRMED",
                        conf=0.92,
                        entity=model_name,
                        files=group_files,
                        expl=f"Multiple schema discrepancies involve model definition '{model_name}'.",
                    )

            rc_id = f"rc_schema_{hashlib.sha1(model_name.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=f"Shared Schema Incompatibility in '{model_name}'",
                category="Payload Validation",
                state="CONFIRMED",
                confidence=0.92,
                severity="high" if any(f.severity == "high" for f in group) else "medium",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=f"Model '{model_name}' has {len(group)} field mismatches across frontend TypeScript interface and backend Pydantic model.",
                recommended_action=f"Align field names, types, and nullability attributes in '{model_name}'.",
                suggested_order=3,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"{len(group)} field mismatches in model '{model_name}'",
                shared_entity=model_name,
            ))

    # -------------------------------------------------------------------------
    # 6. Shared Configuration Defect (CFG001, CFG002, CFG003) -> CONFIRMED
    # -------------------------------------------------------------------------
    # 6a. CFG001: Undeclared Environment Variable (drift from .env.example)
    cfg001_groups: dict[str, list[Finding]] = {}
    for f in by_rule.get("CFG001", []):
        key = f.details.get("key") if f.details else None
        if key:
            cfg001_groups.setdefault(key, []).append(f)

    for env_var, group in cfg001_groups.items():
        if len(group) >= 2 or (group and group[0].details and group[0].details.get("usage_count", 0) > 1):
            group_files = []
            for f in group:
                for ev in f.evidence:
                    if ev.file:
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_configuration_defect",
                        state="CONFIRMED",
                        conf=0.90,
                        entity=env_var,
                        files=group_files,
                        expl=f"Undeclared environment variable '{env_var}' is accessed across multiple files.",
                    )

            rc_id = f"rc_cfg_env_{hashlib.sha1(env_var.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=f"Undeclared Environment Variable '{env_var}'",
                category="Configuration",
                state="CONFIRMED",
                confidence=0.90,
                severity="medium",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=f"Environment variable '{env_var}' is accessed across {len(group_files)} files but omitted from .env.example. Contributors and CI environments will lack necessary configuration.",
                recommended_action=f"Add '{env_var}=<placeholder>' to .env.example documentation.",
                suggested_order=3,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"Affects {len(group_files)} configuration call sites",
                shared_entity=env_var,
            ))

    # 6b. CFG002: Hardcoded Localhost URL in Frontend Code
    cfg002_findings = by_rule.get("CFG002", [])
    if len(cfg002_findings) >= 2:
        cfg002_groups: dict[str, list[Finding]] = {}
        for f in cfg002_findings:
            url_entity = (f.details.get("url") if f.details else None) or "localhost"
            cfg002_groups.setdefault(url_entity, []).append(f)

        for url_key, group in cfg002_groups.items():
            group_files = []
            for f in group:
                for ev in f.evidence:
                    if ev.file:
                        group_files.append(_normalise_rel_path(ev.file, root_path))
            group_files = sorted(set(group_files))

            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    add_relationship(
                        src_id=group[i].id,
                        tgt_id=group[j].id,
                        rel_type="shared_configuration_defect",
                        state="CONFIRMED",
                        conf=0.92,
                        entity=url_key,
                        files=group_files,
                        expl=f"Multiple frontend files hardcode development URL '{url_key}'.",
                    )

            rc_id = f"rc_cfg_localhost_{hashlib.sha1(url_key.encode()).hexdigest()[:10]}"
            ev_list = []
            for f in group:
                ev_list.extend(f.evidence)

            candidates.append(RootCauseCandidate(
                id=rc_id,
                title=f"Systemic Hardcoded Localhost API Configuration ({url_key})",
                category="Configuration",
                state="CONFIRMED",
                confidence=0.92,
                severity="medium",
                finding_ids=[f.id for f in group],
                affected_components=group_files,
                evidence=ev_list[:6],
                description=f"Multiple frontend call sites ({len(group_files)} files) hardcode development URL '{url_key}' rather than utilizing environment configuration. This prevents deployment to staging or production.",
                recommended_action="Replace hardcoded localhost URLs with environment variables (e.g. import.meta.env.VITE_API_BASE_URL).",
                suggested_order=3,
                node_ids=[f"finding:{f.id}" for f in group],
                edge_ids=[],
                impact_summary=f"Hardcoded URLs found across {len(group_files)} frontend files",
                shared_entity=url_key,
            ))

    # 6c. CFG003: Incompatible CORS Configuration (Wildcard origin with credentials)
    for f in by_rule.get("CFG003", []):
        fe_file = f.evidence[0].file if f.evidence else ""
        comp_files = [_normalise_rel_path(fe_file, root_path)] if fe_file else []

        # Only link cross-layer API findings when there is sufficient evidence that the request
        # carries credentials or auth headers, because browsers only reject wildcard CORS for
        # credentialed requests.
        related_credentialed_findings = [
            af for af in findings
            if af.rule_id == "API012"
            or (af.details and (af.details.get("requires_auth") or af.details.get("has_auth_header") or af.details.get("with_credentials")))
        ]
        finding_ids = [f.id] + [af.id for af in related_credentialed_findings[:5]]
        for af in related_credentialed_findings[:5]:
            add_relationship(
                src_id=f.id,
                tgt_id=af.id,
                rel_type="shared_configuration_defect",
                state="CONFIRMED",
                conf=0.95,
                entity="CORS Origin",
                files=comp_files,
                expl="Incompatible CORS configuration (wildcard with credentials) causes browser to reject client requests to backend routes.",
            )

        rc_id = f"rc_cfg_cors_{hashlib.sha1(f.id.encode()).hexdigest()[:10]}"
        candidates.append(RootCauseCandidate(
            id=rc_id,
            title="Incompatible CORS Configuration (Wildcard Origin with Credentials)",
            category="Configuration",
            state="CONFIRMED",
            confidence=0.96,
            severity="high",
            finding_ids=finding_ids,
            affected_components=comp_files,
            evidence=f.evidence,
            description="CORSMiddleware is configured with allow_origins=['*'] and allow_credentials=True. Browsers reject cross-origin requests with credentials when Access-Control-Allow-Origin is a wildcard.",
            recommended_action="Specify explicit origins in allow_origins (e.g. ['http://localhost:3000']) or set allow_credentials=False.",
            suggested_order=1,
            node_ids=[f"finding:{fid}" for fid in finding_ids],
            edge_ids=[],
            impact_summary="Blocks credentialed cross-origin requests from frontend client to backend",
            shared_entity="CORS",
        ))

    # -------------------------------------------------------------------------
    # 7. Dependent Call Chain (Workflow sequences in caller scopes) -> POSSIBLE / LIKELY
    # -------------------------------------------------------------------------
    # Group findings with frontend call evidence by file
    findings_by_fe_file: dict[str, list[Finding]] = {}
    for f in findings:
        fe_ev = next((e for e in f.evidence if e.role == "frontend" and e.file), None)
        if fe_ev:
            norm_f = _normalise_rel_path(fe_ev.file, root_path)
            findings_by_fe_file.setdefault(norm_f, []).append(f)

    for fe_file, file_findings in findings_by_fe_file.items():
        if len(file_findings) >= 2:
            # Check for call pairs with hierarchy or sequential relationship
            for i in range(len(file_findings)):
                for j in range(i + 1, len(file_findings)):
                    f1 = file_findings[i]
                    f2 = file_findings[j]
                    p1 = (f1.details.get("path") or f1.details.get("normalized_path") or "") if f1.details else ""
                    p2 = (f2.details.get("path") or f2.details.get("normalized_path") or "") if f2.details else ""

                    # Exclude findings on the exact same endpoint (handled in shared_endpoint_defects)
                    if p1 and p2 and p1 != p2:
                        # Check prefix relationship (e.g. /api/workflows and /api/workflows/{id})
                        # or sequential line invocation in same file
                        line1 = f1.evidence[0].line if f1.evidence else 0
                        line2 = f2.evidence[0].line if f2.evidence else 0
                        is_hierarchical = p2.startswith(p1.rstrip("/")) or p1.startswith(p2.rstrip("/"))
                        is_nearby = abs(line1 - line2) <= 40

                        if is_hierarchical or is_nearby:
                            chain_label = f"{p1} -> {p2}" if line1 <= line2 else f"{p2} -> {p1}"
                            add_relationship(
                                src_id=f1.id,
                                tgt_id=f2.id,
                                rel_type="dependent_call_chain",
                                state="POSSIBLE",
                                conf=0.82,
                                entity=chain_label,
                                files=[fe_file],
                                expl=f"Chained client workflow in {Path(fe_file).name} invokes dependent endpoints ('{p1}' and '{p2}'). An upstream failure may cascade to downstream calls.",
                            )

                            rc_id = f"rc_chain_{hashlib.sha1(f'{fe_file}:{chain_label}'.encode()).hexdigest()[:10]}"
                            candidates.append(RootCauseCandidate(
                                id=rc_id,
                                title=f"Cascading Call Chain Defect in {Path(fe_file).name}",
                                category="API Contracts",
                                state="POSSIBLE",
                                confidence=0.82,
                                severity="high" if (f1.severity == "high" or f2.severity == "high") else "medium",
                                finding_ids=[f1.id, f2.id],
                                affected_components=[fe_file],
                                evidence=f1.evidence[:2] + f2.evidence[:2],
                                description=f"Component {Path(fe_file).name} executes a multi-step API sequence ({chain_label}). The upstream mismatch directly risks cascading errors to subsequent requests.",
                                recommended_action=f"Verify the full sequence of API calls in {fe_file} to ensure data dependencies match expected backend responses.",
                                suggested_order=3,
                                node_ids=[f"finding:{f1.id}", f"finding:{f2.id}"],
                                edge_ids=[],
                                impact_summary=f"Dependent call chain ({chain_label}) in {Path(fe_file).name}",
                                shared_entity=chain_label,
                            ))

    # Deduplicate candidate IDs and sort by impact & priority
    unique_candidates: dict[str, RootCauseCandidate] = {}
    for c in candidates:
        if c.id not in unique_candidates:
            unique_candidates[c.id] = c

    sorted_candidates = sorted(
        unique_candidates.values(),
        key=lambda x: (
            0 if x.state == "CONFIRMED" else (1 if x.state == "LIKELY" else 2),
            0 if x.severity == "high" else (1 if x.severity == "medium" else 2),
            -len(x.finding_ids),
            -x.confidence,
        )
    )

    # Re-assign sequential suggested_order (1, 2, 3...)
    for idx, cand in enumerate(sorted_candidates):
        cand.suggested_order = idx + 1

    # -------------------------------------------------------------------------
    # Symptom Grouping and Metadata Assignment (Phase 5.1 / P0.2)
    # -------------------------------------------------------------------------
    finding_map: dict[str, Finding] = {f.id: f for f in findings}

    for cand in sorted_candidates:
        # Check prefix drift cascading onto API001 missing route findings
        if cand.id.startswith("rc_pfx_"):
            pfx = getattr(cand, "shared_entity", None)
            if pfx:
                for f in findings:
                    if f.rule_id == "API001" and not f.is_symptom and f.parent_root_cause_id is None:
                        path = (f.details.get("path") or f.details.get("normalized_path") or "") if f.details else ""
                        if path.startswith(pfx + "/") or path == pfx:
                            f.is_symptom = True
                            f.parent_root_cause_id = cand.id
                            f.suppression_reason = f"Cascading missing route symptom caused by systemic API prefix drift '{pfx}'"
                            if f.id not in cand.finding_ids:
                                cand.finding_ids.append(f.id)

        # Only group & suppress symptoms for CONFIRMED or high-confidence LIKELY root causes
        if cand.state in ("CONFIRMED", "LIKELY"):
            if not cand.finding_ids:
                continue

            primary_id = cand.finding_ids[0]
            if primary_id in finding_map:
                primary_f = finding_map[primary_id]
                if primary_f.parent_root_cause_id is None:
                    primary_f.parent_root_cause_id = cand.id
                    primary_f.is_symptom = False

            for fid in cand.finding_ids[1:]:
                f = finding_map.get(fid)
                if f and not f.is_symptom and f.parent_root_cause_id is None:
                    f.is_symptom = True
                    f.parent_root_cause_id = cand.id
                    f.suppression_reason = (
                        f"Dependent symptom grouped under {cand.state.lower()} root cause '{cand.title}'"
                    )

    return relationships, sorted_candidates
