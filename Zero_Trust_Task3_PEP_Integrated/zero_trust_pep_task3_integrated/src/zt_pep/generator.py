from __future__ import annotations

import json
import pprint
import re
from pathlib import Path
from typing import Any

from .manifest import save_manifest
from .models import LogicalPEP, PEPPlan


def _function_name(placement_id: str) -> str:
    return "protect_" + re.sub(r"[^a-zA-Z0-9]+", "_", placement_id).strip("_").lower()


def generate_artifacts(plan: PEPPlan, updated_manifest: dict[str, Any], output_dir: str | Path) -> None:
    root = Path(output_dir)
    adapters = root / "adapters"
    root.mkdir(parents=True, exist_ok=True)
    adapters.mkdir(parents=True, exist_ok=True)

    plan_path = root / "generated_pep_plan.json"
    plan_path.write_text(json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8")
    save_manifest(root / "zt_manifest.task3.yaml", updated_manifest)

    findings = [item.model_dump(mode="json") for item in plan.findings]
    (root / "unprotected_paths.json").write_text(json.dumps(findings, indent=2, sort_keys=True), encoding="utf-8")
    (root / "pep_coverage_report.json").write_text(json.dumps(plan.coverage, indent=2, sort_keys=True), encoding="utf-8")
    (root / "PEP_COVERAGE_REPORT.md").write_text(_coverage_markdown(plan), encoding="utf-8")
    (root / "UNPROTECTED_PATH_REPORT.md").write_text(_findings_markdown(plan), encoding="utf-8")
    (root / "PHYSICAL_PEP_MAP.md").write_text(_physical_map_markdown(plan), encoding="utf-8")
    if plan.compatibility:
        (root / "task4_compatibility_report.json").write_text(
            json.dumps(plan.compatibility, indent=2, sort_keys=True), encoding="utf-8"
        )
        (root / "TASK4_COMPATIBILITY_REPORT.md").write_text(
            _compatibility_markdown(plan.compatibility), encoding="utf-8"
        )

    (adapters / "__init__.py").write_text("\"\"\"Generated Task 3 adapters.\"\"\"\n", encoding="utf-8")
    by_module: dict[str, list[LogicalPEP]] = {}
    for pep in plan.logical_peps:
        by_module.setdefault(pep.adapter_module, []).append(pep)
    for module_name, peps in by_module.items():
        (adapters / module_name).write_text(_adapter_module(module_name, peps), encoding="utf-8")
    for required in {
        "mcp_wrappers.py",
        "fastapi_dependencies.py",
        "data_wrappers.py",
        "event_wrappers.py",
        "agent_route_middleware.py",
        "input_output_pep.py",
        "tool_wrappers.py",
        "shared_middleware.py",
    } - set(by_module):
        (adapters / required).write_text(_empty_adapter_module(required), encoding="utf-8")

    (adapters / "pep_registry.py").write_text(_registry_module(plan), encoding="utf-8")


def _coverage_markdown(plan: PEPPlan) -> str:
    c = plan.coverage
    return f"""# Task 3 PEP Coverage Report

- Manifest: `{plan.manifest_name}`
- Manifest version: `{plan.manifest_version}`
- Environment binding: `{plan.environment_binding}`
- Known interaction edges: **{c['interaction_edges_total']}**
- Sensitive known paths: **{c['sensitive_interaction_edges']}**
- Protected sensitive paths: **{c['protected_sensitive_edges']}**
- Sensitive-path PEP coverage: **{c['sensitive_path_coverage_percent']}%**
- Known direct bypass paths: **{c['known_direct_bypass_paths']}**
- Logical PEPs: **{c['logical_pep_count']}**
- Physical PEP components: **{c['physical_pep_count']}**
- Components eliminated by safe sharing: **{c['deduplicated_component_savings']}**

## Scope of the coverage claim

{c['coverage_claim_scope']}. Resources with no discovered interaction edge are listed separately and are not silently counted as protected.
"""


def _findings_markdown(plan: PEPPlan) -> str:
    lines = ["# Task 3 Unprotected-Path and Scanner-Gap Report", ""]
    blocking = [item for item in plan.findings if item.blocks_milestone]
    lines.append(f"Blocking findings: **{len(blocking)}**")
    lines.append("")
    if not plan.findings:
        lines.append("No findings.")
    for item in plan.findings:
        target = item.edge_id or item.resource_id or "n/a"
        lines.extend(
            [
                f"## {item.severity.upper()}: {item.category}",
                f"- Target: `{target}`",
                f"- Blocks M3: `{str(item.blocks_milestone).lower()}`",
                f"- Detail: {item.message}",
                "",
            ]
        )
    return "\n".join(lines)


def _physical_map_markdown(plan: PEPPlan) -> str:
    lines = ["# Logical-to-Physical PEP Map", ""]
    for pep in plan.physical_peps:
        lines.append(f"## `{pep.physical_pep_id}`")
        lines.append(f"- Type: `{pep.pep_type}`")
        lines.append(f"- Generated adapter: `adapters/{pep.adapter_module}`")
        lines.append(f"- Mode / failure: `{pep.mode}` / `{pep.fail_mode}`")
        lines.append("- Logical placements:")
        lines.extend(f"  - `{item}`" for item in pep.logical_placements)
        lines.append("")
    return "\n".join(lines)



def _compatibility_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    edge_checks = report.get("edge_registry_checks", [])
    no_policy = [item for item in edge_checks if not item.get("candidate_policy_ids")]
    lines = [
        "# Task 3 / Task 4 Compatibility Report",
        "",
        f"- Task 4 package: `{report.get('task4_package', 'unknown')}`",
        f"- Interface schemas match: **{summary.get('interface_schemas_match')}**",
        f"- All generated requests resolve in Task 4 registries: **{summary.get('all_pep_requests_resolve_in_task4_registry')}**",
        f"- Overall compatible: **{summary.get('compatible')}**",
        "",
        "## Policy coverage note",
        "",
        "Registry compatibility does not imply every interaction is allowed. Task 4 remains default-deny.",
        f"Known generated edges without a candidate explicit policy: **{len(no_policy)}**.",
        "These edges will return DENY until Task 4 policy bundles are extended.",
        "",
    ]
    for item in no_policy:
        lines.append(f"- `{item['edge_id']}` → default DENY")
    return "\n".join(lines) + "\n"

def _registry_module(plan: PEPPlan) -> str:
    payload = pprint.pformat({item.placement_id: item.model_dump(mode="json") for item in plan.logical_peps}, sort_dicts=True, width=120)
    return f'''"""Generated registry. Do not edit by hand; regenerate from the unified manifest."""

PLACEMENTS = {payload}


def get_placement(placement_id: str) -> dict:
    try:
        return PLACEMENTS[placement_id]
    except KeyError as exc:
        raise KeyError(f"unknown generated PEP placement: {{placement_id}}") from exc
'''


def _adapter_module(module_name: str, peps: list[LogicalPEP]) -> str:
    header = '''"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer
'''
    if module_name == "fastapi_dependencies.py":
        header += '''
try:
    from fastapi import HTTPException, Request
except ImportError:  # FastAPI is optional until this adapter is used.
    HTTPException = RuntimeError
    Request = Any


def make_fastapi_dependency(enforcer: PEPEnforcer, placement_id: str):
    async def dependency(request: Request) -> dict[str, Any]:
        try:
            parameters = dict(getattr(request, "path_params", {}) or {})
            query = getattr(request, "query_params", None)
            if query is not None:
                parameters.update(dict(query))
            decision, _ = enforcer.authorize(placement_id, parameters=parameters)
            if decision.get("decision") not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
                raise HTTPException(status_code=403, detail=decision.get("reason", "denied"))
            return decision
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"PEP fail-closed: {exc}") from exc
    return dependency
'''
    elif module_name == "agent_route_middleware.py":
        header += '''
class AgentRoutePEPMiddleware:
    def __init__(self, app: Any, enforcer: PEPEnforcer, placement_resolver: Callable[[Any], str | None]):
        self.app = app
        self.enforcer = enforcer
        self.placement_resolver = placement_resolver

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        placement_id = self.placement_resolver(scope)
        if placement_id:
            decision, _ = self.enforcer.authorize(placement_id, parameters={"route": scope.get("path")})
            if decision.get("decision") not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
                raise PermissionError(f"agent route blocked by {placement_id}")
        await self.app(scope, receive, send)
'''
    else:
        header += '''
def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)
'''

    functions = []
    for pep in sorted(peps, key=lambda item: item.placement_id):
        name = _function_name(pep.placement_id)
        if module_name == "fastapi_dependencies.py":
            functions.append(
                f"\ndef {name}(enforcer: PEPEnforcer):\n    return make_fastapi_dependency(enforcer, {pep.placement_id!r})\n"
            )
        else:
            functions.append(
                f"\ndef {name}(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:\n"
                f"    return protect(enforcer, {pep.placement_id!r}, operation)\n"
            )
    return header + "".join(functions)


def _empty_adapter_module(module_name: str) -> str:
    return f'''"""Generated placeholder for {module_name}; no current manifest edge requires this adapter type."""
from __future__ import annotations
from typing import Any, Callable
from zt_pep.runtime import PEPEnforcer


def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_sync(placement_id, operation)
'''
