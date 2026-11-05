"""``zt-adk build``: discover -> classify -> manifest -> PEP plan -> PDP config -> PSL store -> sign.

Fails closed: a discovery error (duplicate agent names, an AgentTool without plugins, an
unsupported tool object), an invalid manifest, a PEP plan finding that blocks protection,
a policy that does not compile against the catalogue, or a missing key stops the build.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from . import model as M
from .bundle import BUNDLE_FORMAT, file_index, sign_index
from .discovery import discover, load_object, resolve_app
from .keys import POLICY_ISSUER, list_approvers, load_private, require_keys
from .manifest import IdMaps, build_manifest
from .policygen import generate_store
from .profile import Profile


class BuildError(RuntimeError):
    pass


@dataclass
class BuildResult:
    bundle_dir: Path
    model: M.SystemModel
    ids: IdMaps
    policy_version: str
    logical_peps: int
    physical_peps: int
    rules: int
    warnings: list[str]


def _task3_schema() -> Path:
    import zt_pep

    root = Path(zt_pep.__file__).resolve().parents[2]
    p = root / "interface_contract" / "schemas" / "zt_manifest.schema.json"
    if not p.exists():
        raise BuildError(f"Task 3 interface contract not found at {p}")
    return p


def runtime_profile(profile: Profile) -> dict[str, Any]:
    return {
        "mode": profile.mode,
        "environment": profile.environment,
        "approvals": profile.approvals.model_dump(),
        "content": profile.content.model_dump(),
        "session": profile.session.model_dump(),
        "identity": profile.identity.model_dump(),
        "model_override": profile.model_override.model_dump() if profile.model_override else None,
    }


def static_crosscheck(model: M.SystemModel, source_root: Path, out_dir: Path) -> dict[str, Any]:
    """Run the static scanner (zero_trust_task2) over the source tree and compare."""
    try:
        import zt_scan  # noqa: F401  (installed alongside, or found next to zt_adk)
        scanner = Path(sys.modules["zt_scan"].__file__)
    except ImportError:
        candidate = Path(__file__).resolve().parents[3] / "zero_trust_task2" / "zt_scan.py"
        if not candidate.exists():
            return {"available": False, "reason": "static scanner (zero_trust_task2/zt_scan.py) not found"}
        scanner = candidate
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run([sys.executable, str(scanner), "--repo-root", str(source_root), "--output-dir",
                               str(Path(tmp) / "draft")], capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            return {"available": False, "reason": f"scanner failed: {proc.stderr[-500:]}"}
        inv = json.loads((Path(tmp) / "agent_inventory.json").read_text(encoding="utf-8"))
        tools_inv = json.loads((Path(tmp) / "tool_inventory.json").read_text(encoding="utf-8"))
        cov = json.loads((Path(tmp) / "coverage_report.json").read_text(encoding="utf-8"))
        unresolved = json.loads((Path(tmp) / "unresolved_interfaces.json").read_text(encoding="utf-8"))

    def items(raw: Any) -> list[dict[str, Any]]:
        lst = raw if isinstance(raw, list) else next((v for v in raw.values() if isinstance(v, list)), [])
        return [x.get("payload", x) for x in lst]

    static_agents = {str(a.get("agent_id")) for a in items(inv)}
    static_tools = {str(t.get("tool_id") or t.get("name") or t.get("runtime_id")) for t in items(tools_inv)}
    live_agents = set(model.agents)
    live_tools = {t.name for t in model.tools.values() if t.kind not in (M.AGENT_TOOL,)}
    report = {
        "available": True,
        "static_agents": len(static_agents), "live_agents": len(live_agents),
        "agents_only_in_source": sorted(static_agents - live_agents),
        "agents_only_live": sorted(live_agents - static_agents),
        "tools_only_live": sorted(live_tools - static_tools),
        "static_unresolved_findings": len(unresolved) if isinstance(unresolved, list) else
        len(unresolved.get("findings", [])) if isinstance(unresolved, dict) else 0,
        "static_coverage_percent": cov.get("coverage_percent"),
        "note": ("The live object graph is authoritative. Agents only in the source are not reachable from the "
                 "application's root (dead code, or built for another app); agents only live are constructed "
                 "dynamically (factories, loops, configuration)."),
    }
    (out_dir / "crosscheck.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def build(profile: Profile, *, root_agent: Any = None, app_name: str | None = None, out_dir: Path | None = None,
          skip_static: bool = False) -> BuildResult:
    from zt_backplane.crypto import TrustedKeyStore
    from zt_backplane.psl_policy import PslPolicyStore
    from zt_interface.compiler import compile_task4
    from zt_interface.validator import validate_manifest as validate_unified
    from zt_pep.generator import generate_artifacts
    from zt_pep.manifest import validate_manifest as validate_task3
    from zt_pep.placement import build_pep_plan
    from zt_psl.signing import sign_file

    keys_dir = profile.path(profile.keys_dir)
    require_keys(keys_dir)
    policy_key_file = keys_dir / "signing" / "policy_private.pem"
    if not policy_key_file.exists():
        raise BuildError(f"policy signing key missing: {policy_key_file} (run 'zt-adk keys init')")

    if root_agent is None:
        obj = load_object(profile.app, [profile.path(p) for p in profile.python_paths])
        root_agent, found_name, _plugins = resolve_app(obj)
        app_name = app_name or found_name
    app_name = profile.app_name or app_name or root_agent.name

    declared = {name: ov.tools for name, ov in profile.toolsets.items()}
    resolution = {name: ov.resolve for name, ov in profile.toolsets.items()}
    model, _agents, _tools = discover(root_agent, app_name=app_name, declared_toolset_tools=declared,
                                      toolset_resolution=resolution)
    if model.errors:
        raise BuildError("discovery found problems that would leave parts of the system unprotected:\n  - "
                         + "\n  - ".join(model.errors))
    if profile.strict:
        blind = [name for name, rec in sorted(model.toolsets.items()) if not rec["tools"]
                 and name not in profile.toolsets and name.split("/", 1)[1] not in profile.toolsets]
        if blind:
            raise BuildError(
                "strict: the tools of these toolsets are unknown (resolution failed and zt_adk.yaml declares none), "
                "so every tool they offer would be denied at run time: " + ", ".join(blind) + ". Declare the tools "
                "(toolsets.<name>.tools), or list the toolset with resolve: false to accept the denial, or set "
                "strict: false.")

    manifest, ids = build_manifest(model, profile)
    errors = validate_unified(manifest)
    if errors:
        raise BuildError("generated manifest invalid: " + "; ".join(errors[:8]))
    errors = validate_task3(manifest, _task3_schema())
    if errors:
        raise BuildError("generated manifest rejected by Task 3: " + "; ".join(errors[:8]))
    plan, updated_manifest = build_pep_plan(manifest)
    blocking = [f for f in plan.findings if f.blocks_milestone]
    if blocking:
        raise BuildError("PEP plan has blocking findings: " + "; ".join(f"{f.category}: {f.message}" for f in blocking))

    out = Path(out_dir) if out_dir else profile.path(profile.bundle_dir)
    staging = out.with_name(out.name + ".building")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        (staging / "system_model.json").write_text(json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n",
                                                   encoding="utf-8")
        (staging / "bindings.json").write_text(json.dumps(ids.as_dict(), indent=2, sort_keys=True) + "\n",
                                               encoding="utf-8")
        (staging / "runtime_profile.json").write_text(json.dumps(runtime_profile(profile), indent=2,
                                                                 sort_keys=True) + "\n", encoding="utf-8")
        (staging / "manifest.yaml").write_text(yaml.safe_dump(updated_manifest, sort_keys=False, allow_unicode=True),
                                               encoding="utf-8")
        generate_artifacts(plan, updated_manifest, staging / "task3")
        plan_json = json.loads((staging / "task3" / "generated_pep_plan.json").read_text(encoding="utf-8"))
        compile_task4(updated_manifest, staging / "task4_config")

        approvers = list_approvers(keys_dir)
        store = generate_store(model, ids, plan_json, profile,
                               approval_issuers=[a.issuer for a in approvers if a.purpose == "human_approval"],
                               secondary_issuers=[a.issuer for a in approvers if a.purpose == "secondary_authorization"])
        model.warnings.extend(store.warnings)
        policy_dir = staging / "policy_store"
        policy_dir.mkdir()
        policy_key = load_private(policy_key_file)
        for name, text in sorted(store.files.items()):
            path = policy_dir / name
            path.write_bytes(text.encode("utf-8"))
            sign_file(path, policy_key, issuer=POLICY_ISSUER[0], key_id=POLICY_ISSUER[1])
        trust = TrustedKeyStore(keys_dir / "trusted_issuers.yaml")
        try:
            store_obj = PslPolicyStore.load(policy_dir, keys=trust)
        except Exception as exc:
            raise BuildError(f"generated policy store does not compile: {exc}") from exc
        if not skip_static:
            crosscheck = static_crosscheck(model, profile.path(profile.source_root), staging)
        else:
            crosscheck = {"available": False, "reason": "skipped"}
        _write_report(staging, model, ids, plan_json, store_obj, crosscheck, profile)
        index = {
            "format": BUNDLE_FORMAT, "zt_adk_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "app_name": model.app_name, "root_agent": model.root_agent, "adk_version": model.adk_version,
            "fingerprint": model.fingerprint(), "policy_version": store_obj.version,
            "policy_sets": store_obj.bundle_versions, "environment": profile.environment, "mode": profile.mode,
            "logical_peps": len(plan_json.get("logical_peps", [])),
            "physical_peps": len(plan_json.get("physical_peps", [])),
            "files": file_index(staging),
        }
        sign_index(staging, index, policy_key, issuer=POLICY_ISSUER[0], key_id=POLICY_ISSUER[1])
        if out.exists():
            shutil.rmtree(out)
        staging.rename(out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    rules = sum(1 for r in store_obj.policy_set.rules if r.kind != "default_deny")
    return BuildResult(out, model, ids, store_obj.version, len(plan_json.get("logical_peps", [])),
                       len(plan_json.get("physical_peps", [])), rules, list(model.warnings))


def _write_report(root: Path, model: M.SystemModel, ids: IdMaps, plan: dict[str, Any], store: Any,
                  crosscheck: dict[str, Any], profile: Profile) -> None:
    L = [f"# Protection report: {model.app_name}", "",
         f"* root agent: `{model.root_agent}`; google-adk {model.adk_version}",
         f"* fingerprint: `{model.fingerprint()}`",
         f"* agents: {len(model.agents)}; tools: {len(model.tools)}; edges: {len(model.edges)}",
         f"* PEP placements: {len(plan.get('logical_peps', []))} logical, {len(plan.get('physical_peps', []))} physical",
         f"* policy version: `{store.version}`; policy sets: {', '.join(sorted(store.bundle_versions))}", "",
         "## Agents", "", "| agent | kind | domain | parent | workflow |", "|---|---|---|---|---|"]
    for n, a in sorted(model.agents.items()):
        L.append(f"| {n} | {a.kind} | {ids.domains.get(n)} | {a.parent or ''} | {model.workflow_of.get(n) or ''} |")
    L += ["", "## Operations", "", "| tool | kind | action | side effect | criticality | data | approval |",
          "|---|---|---|---|---|---|---|"]
    for k, op in sorted(ids.operations.items()):
        appr = ("dual" if op["secondary_approval"] else "yes") if op["requires_approval"] else "no"
        L.append(f"| {k} | {model.tools[k].kind} | {op['action']} | {op['side_effect']} | {op['criticality']} | "
                 f"{op['classification']} | {appr} |")
    L += ["", "## Routes", ""]
    for e in model.edges:
        if e.kind in (M.EDGE_ENTRY, M.EDGE_TRANSFER, M.EDGE_ORCHESTRATE, M.EDGE_AGENT_TOOL):
            L.append(f"* {e.kind}: {e.caller} -> {e.target}" + (f" (workflow {e.workflow})" if e.workflow else ""))
    L += ["", "## Policy rules", ""]
    for r in sorted(store.policy_set.rules, key=lambda r: (r.psl_file, r.line)):
        if r.kind != "default_deny":
            L.append(f"* `{r.rule_id}` ({r.scope}, {r.kind}{', ' + r.on_violation if r.kind == 'constraint' else ''})")
    if model.warnings:
        L += ["", "## Warnings", ""] + [f"* {w}" for w in model.warnings]
    L += ["", "## Static cross-check", "", "```json", json.dumps(crosscheck, indent=2, sort_keys=True), "```", ""]
    (root / "REPORT.md").write_text("\n".join(L), encoding="utf-8")
