from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class NativeAuthorization:
    allowed: bool
    would_block: bool
    mode: str
    reason: str
    source: str
    placement: dict[str, Any] | None
    request: Any | None
    runtime_authorization: Any | None
    authorization_latency_ms: float
    permit_id: str | None = None
    policy_version: str | None = None
    decision: str | None = None


@dataclass
class PendingNativeTool:
    authorization: NativeAuthorization
    pep: Any
    request: Any
    obligations: list[Any]
    idempotency_reserved: bool = False


class NativeMasBackplane:
    """Real Zero Trust enforcement engine for the native CITI-MAS ADK runtime.

    This class is intentionally independent from the Task 6 workflow harness.  It
    consumes the scanner / unified manifest / Task 3 PEP plan, starts the real
    signed Task 4 PDP in-process, and exposes Task 5 Permit-Lease-backed checks
    that an ADK runtime plugin can call at the *actual* agent and tool lifecycle
    boundaries.
    """

    CLI_SUBJECT = "service.external.cli_user"
    CLI_RUNTIME_ID = "cli_user"
    INPUT_RESOURCE = "resource.shared.mas_input"
    INPUT_RUNTIME_ID = "mas_input_channel"
    OUTPUT_RESOURCE = "resource.shared.mas_output"
    OUTPUT_RUNTIME_ID = "mas_output_channel"

    def __init__(
        self,
        *,
        backplane_root: str | Path,
        mas_repo_root: str | Path,
        output_dir: str | Path,
        mode: str = "enforce",
        refresh: bool = False,
        human_approval: bool = False,
        secondary_authorization: bool = False,
        change_ticket: str | None = None,
        shadow_allow_critical: bool = False,
        runtime_agent_edges: list[tuple[str, str]] | None = None,
    ) -> None:
        self.backplane_root = Path(backplane_root).resolve()
        self.mas_repo_root = Path(mas_repo_root).resolve()
        self.output_dir = Path(output_dir).resolve()
        self.mode = str(mode).lower().strip()
        if self.mode not in {"enforce", "shadow"}:
            raise ValueError("mode must be 'enforce' or 'shadow'")
        self.refresh = bool(refresh)
        self.human_approval = bool(human_approval)
        self.secondary_authorization = bool(secondary_authorization)
        self.change_ticket = change_ticket
        self.shadow_allow_critical = bool(shadow_allow_critical)
        self.runtime_agent_edges = list(runtime_agent_edges or [])

        self.task2_root = self.backplane_root / "zero_trust_task2"
        self.task3_root = (
            self.backplane_root
            / "Zero_Trust_Task3_PEP_Integrated"
            / "zero_trust_pep_task3_integrated"
        )
        self.task4_root = self.backplane_root / "zero_trust_pdp_task4_secure"
        self.task5_root = self.backplane_root / "zero_trust_task5"
        self.interface_root = self.backplane_root / "interface_standard"
        self.integrated_root = self.backplane_root / "integrated_demo"
        self._validate_roots()
        self._install_import_paths()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.plan_json: dict[str, Any] = {}
        self.manifest: dict[str, Any] = {}
        self.task4_runtime: Any = None
        self.task4_client: Any = None
        self.bridge: Any = None
        self.components: Any = None
        self._pep_keys: dict[str, Ed25519PrivateKey] = {}
        self._pep_cache: dict[str, Any] = {}
        self.audit_path = self.output_dir / "native_mas_audit.jsonl"
        self._audit_seq = 0

        self._bootstrap()

    # ------------------------------------------------------------------
    # Bootstrap: Task 2 -> unified graph -> Task 3 -> Task 4 -> Task 5
    # ------------------------------------------------------------------
    def _validate_roots(self) -> None:
        required = [
            self.task2_root / "zt_scan.py",
            self.task3_root / "src",
            self.task4_root / "src",
            self.task5_root / "src",
            self.interface_root / "src",
        ]
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise FileNotFoundError(
                "Backplane root is missing required components: " + ", ".join(missing)
            )
        if not (self.mas_repo_root / "citi_banking_adk").exists():
            raise FileNotFoundError(
                f"MAS repo root does not contain citi_banking_adk: {self.mas_repo_root}"
            )

    def _install_import_paths(self) -> None:
        for path in (
            self.backplane_root,
            self.task3_root / "src",
            self.task4_root / "src",
            self.task5_root / "src",
            self.interface_root / "src",
            self.integrated_root,
        ):
            text = str(path)
            if text not in sys.path:
                sys.path.insert(0, text)

    @staticmethod
    def _metadata(display_name: str, description: str) -> dict[str, Any]:
        return {
            "display_name": display_name,
            "description": description,
            "status": "provisional",
            "source": {
                "provided_by": "native_mas_runtime",
                "reference": "Native CITI-MAS CLI / ADK runtime boundary",
                "verified_at": None,
                "notes": "Automatically added so input/output are protected in the native runtime.",
            },
            "owner": None,
            "tags": ["native_runtime"],
            "extensions": {},
        }

    def _augment_native_boundaries(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Add the CLI input and final-output boundaries to the generated graph.

        Task 2 discovers code-to-code paths.  The CLI message and final serialized
        response are runtime boundaries, so they are added explicitly before Task
        3 PEP placement.  This makes the final native path protectable from input
        through output instead of beginning only at the first tool call.
        """
        manifest = json.loads(json.dumps(manifest))
        spec = manifest["spec"]
        env = spec["defaults"]["environment_binding"]

        def binding(runtime_id: str) -> dict[str, Any]:
            return {
                env: {
                    "runtime_id": runtime_id,
                    "endpoint": None,
                    "function_name": None,
                    "service_name": None,
                    "namespace": None,
                    "secret_refs": [],
                    "extensions": {},
                }
            }

        subject_ids = {x["id"] for x in spec.get("subjects", [])}
        if self.CLI_SUBJECT not in subject_ids:
            spec.setdefault("subjects", []).append(
                {
                    "id": self.CLI_SUBJECT,
                    "type": "service",
                    "roles": ["cli_ingress"],
                    "domain": "external",
                    "enabled": True,
                    "metadata": self._metadata("CLI User", "Native command-line ingress identity."),
                    "bindings": binding(self.CLI_RUNTIME_ID),
                    "attributes": {"native_boundary": "input"},
                }
            )

        resource_ids = {x["id"] for x in spec.get("resources", [])}
        native_resources = [
            (
                self.INPUT_RESOURCE,
                self.INPUT_RUNTIME_ID,
                "invoke",
                "MAS Input",
                "Native CLI-to-MAS input channel.",
            ),
            (
                self.OUTPUT_RESOURCE,
                self.OUTPUT_RUNTIME_ID,
                "emit",
                "MAS Output",
                "Native MAS-to-CLI serialized output channel.",
            ),
        ]
        for resource_id, runtime_id, action, title, description in native_resources:
            if resource_id in resource_ids:
                continue
            spec.setdefault("resources", []).append(
                {
                    "id": resource_id,
                    "type": "other",
                    "domain": "shared",
                    "classification": "internal",
                    "actions": [
                        {
                            "name": action,
                            "side_effect": False,
                            "criticality": "medium",
                            "requires_human_approval": False,
                            "idempotent": True,
                            "parameter_schema_ref": None,
                        }
                    ],
                    "metadata": self._metadata(title, description),
                    "bindings": binding(runtime_id),
                    "attributes": {"native_boundary": action},
                }
            )

        boundary_ids = {x["id"] for x in spec.get("trust_boundaries", [])}
        for boundary_id, from_zone, to_zone, title in (
            ("boundary.external.input", "external", "agent", "External Input Boundary"),
            ("boundary.output.external", "agent", "external", "Output Egress Boundary"),
        ):
            if boundary_id not in boundary_ids:
                spec.setdefault("trust_boundaries", []).append(
                    {
                        "id": boundary_id,
                        "from_zone": from_zone,
                        "to_zone": to_zone,
                        "metadata": self._metadata(title, "Native CITI-MAS runtime trust boundary."),
                        "attributes": {"native_runtime": True},
                    }
                )

        root_subject = None
        for item in spec.get("subjects", []):
            runtime = item.get("bindings", {}).get(env, {}).get("runtime_id")
            if runtime == "user_proxy_agent":
                root_subject = item["id"]
                break
        if root_subject is None:
            # The scanner can discover the root constructor without producing a
            # caller edge for it, so scanner_merge may not materialize it as a
            # subject.  The native runtime nevertheless has a concrete root
            # identity and needs it for output enforcement.
            root_subject = "agent.shared.user_proxy_agent"
            spec.setdefault("subjects", []).append(
                {
                    "id": root_subject,
                    "type": "agent",
                    "roles": ["native_root_router"],
                    "domain": "shared",
                    "enabled": True,
                    "metadata": self._metadata(
                        "User Proxy Agent", "Native CITI-MAS root agent identity."
                    ),
                    "bindings": binding("user_proxy_agent"),
                    "attributes": {"native_boundary": "root_agent"},
                }
            )

        # Reconcile the scanner graph with the *actual* instantiated ADK tree.
        # This is particularly important for factory-built root sub_agents, where
        # static AST analysis may see the constructor call but not recover the
        # runtime child identity.  The runtime tree is authoritative for native
        # agent-to-agent enforcement.
        subject_by_runtime = {
            str(item.get("bindings", {}).get(env, {}).get("runtime_id") or ""): item["id"]
            for item in spec.get("subjects", [])
            if item.get("bindings", {}).get(env, {}).get("runtime_id")
        }
        resource_by_runtime = {
            str(item.get("bindings", {}).get(env, {}).get("runtime_id") or ""): item["id"]
            for item in spec.get("resources", [])
            if item.get("bindings", {}).get(env, {}).get("runtime_id")
        }

        def runtime_domain(runtime_id: str) -> str:
            text = runtime_id.lower()
            if text.startswith("front_") or "front_office" in text:
                return "front_office"
            if text.startswith("mid_") or "mid_office" in text or "representative" in text:
                return "mid_office"
            if text.startswith("back_") or "back_office" in text or any(
                token in text for token in ("eod", "ledger", "reconciliation", "report_writing", "exception")
            ):
                return "back_office"
            return "shared"

        def ensure_runtime_subject(runtime_id: str) -> str:
            if runtime_id in subject_by_runtime:
                return subject_by_runtime[runtime_id]
            dom = runtime_domain(runtime_id)
            canonical = f"agent.{dom}.{runtime_id.lower()}"
            spec.setdefault("subjects", []).append(
                {
                    "id": canonical,
                    "type": "agent",
                    "roles": ["runtime_discovered"],
                    "domain": dom,
                    "enabled": True,
                    "metadata": self._metadata(runtime_id, "Identity materialized from the instantiated ADK agent tree."),
                    "bindings": binding(runtime_id),
                    "attributes": {"native_runtime_tree": True},
                }
            )
            subject_by_runtime[runtime_id] = canonical
            return canonical

        def ensure_agent_resource(runtime_id: str) -> str:
            if runtime_id in resource_by_runtime:
                return resource_by_runtime[runtime_id]
            dom = runtime_domain(runtime_id)
            canonical = f"resource.{dom}.agent_{runtime_id.lower()}"
            spec.setdefault("resources", []).append(
                {
                    "id": canonical,
                    "type": "other",
                    "domain": dom,
                    "classification": "internal",
                    "actions": [
                        {
                            "name": "invoke",
                            "side_effect": False,
                            "criticality": "medium",
                            "requires_human_approval": False,
                            "idempotent": True,
                            "parameter_schema_ref": None,
                        }
                    ],
                    "metadata": self._metadata(runtime_id, "Agent invocation target from the instantiated ADK tree."),
                    "bindings": binding(runtime_id),
                    "attributes": {"native_runtime_tree": True, "resource_kind": "agent"},
                }
            )
            resource_by_runtime[runtime_id] = canonical
            return canonical

        interaction_ids = {x["id"] for x in spec.get("interactions", [])}
        existing_runtime_routes = {
            (
                str(next((s.get("bindings", {}).get(env, {}).get("runtime_id") for s in spec.get("subjects", []) if s["id"] == edge.get("caller_id")), "")),
                str(next((r.get("bindings", {}).get(env, {}).get("runtime_id") for r in spec.get("resources", []) if r["id"] == edge.get("resource_id")), "")),
            )
            for edge in spec.get("interactions", [])
            if edge.get("pep", {}).get("type") == "agent_route"
        }
        for caller_runtime, target_runtime in self.runtime_agent_edges:
            if (caller_runtime, target_runtime) in existing_runtime_routes:
                continue
            caller_id = ensure_runtime_subject(caller_runtime)
            target_resource = ensure_agent_resource(target_runtime)
            edge_id = f"edge.native.route_{caller_runtime}_{target_runtime}".lower()
            placement_id = f"pep.native.route_{caller_runtime}_{target_runtime}".lower()
            if edge_id in interaction_ids:
                continue
            spec.setdefault("interactions", []).append(
                {
                    "id": edge_id,
                    "caller_id": caller_id,
                    "target_id": target_resource,
                    "resource_id": target_resource,
                    "action": "invoke",
                    "workflow_id": None,
                    "interface_id": None,
                    "trust_boundary_id": "boundary.agent.agent",
                    "risk": "medium",
                    "data_types": ["agent_invocation"],
                    "side_effect": False,
                    "pep": {
                        "required": True,
                        "type": "agent_route",
                        "mode": "enforce",
                        "placement_id": placement_id,
                        "fail_mode": "closed",
                    },
                    "metadata": self._metadata(
                        f"{caller_runtime} -> {target_runtime}",
                        "Native agent route recovered from the instantiated ADK tree.",
                    ),
                    "attributes": {"native_runtime_tree": True},
                }
            )
            interaction_ids.add(edge_id)

        additions = [
            {
                "id": "edge.native.cli_input",
                "caller_id": self.CLI_SUBJECT,
                "target_id": self.INPUT_RESOURCE,
                "resource_id": self.INPUT_RESOURCE,
                "action": "invoke",
                "workflow_id": None,
                "interface_id": None,
                "trust_boundary_id": "boundary.external.input",
                "risk": "medium",
                "data_types": ["user_message"],
                "side_effect": False,
                "pep": {
                    "required": True,
                    "type": "input",
                    "mode": "enforce",
                    "placement_id": "pep.native.cli_input",
                    "fail_mode": "closed",
                },
                "metadata": self._metadata("Native CLI Input", "CLI message entering the native MAS runtime."),
                "attributes": {"native_runtime": True},
            },
            {
                "id": "edge.native.cli_output",
                "caller_id": root_subject,
                "target_id": self.OUTPUT_RESOURCE,
                "resource_id": self.OUTPUT_RESOURCE,
                "action": "emit",
                "workflow_id": None,
                "interface_id": None,
                "trust_boundary_id": "boundary.output.external",
                "risk": "medium",
                "data_types": ["json_output"],
                "side_effect": False,
                "pep": {
                    "required": True,
                    "type": "output",
                    "mode": "enforce",
                    "placement_id": "pep.native.cli_output",
                    "fail_mode": "closed",
                },
                "metadata": self._metadata("Native CLI Output", "Final serialized result leaving the MAS runtime."),
                "attributes": {"native_runtime": True},
            },
        ]
        for item in additions:
            if item["id"] not in interaction_ids:
                spec.setdefault("interactions", []).append(item)
        return manifest

    @staticmethod
    def _write_signed_policy_bundle(task4_root: Path, policy_path: Path, raw: dict[str, Any]) -> None:
        from zt_backplane.canonical import sha256_hex
        from zt_backplane.crypto import load_private_key, sign_mapping

        policy_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        private_key = load_private_key(task4_root / "security" / "dev_keys" / "policy_private.pem")
        sidecar = {
            "schema_version": "1.0",
            "issuer": "policy.prototype",
            "key_id": "policy-1",
            "algorithm": "Ed25519",
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "bundle_digest": sha256_hex(raw),
            "signature": sign_mapping(private_key, raw),
        }
        policy_path.with_suffix(".sig.json").write_text(
            json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    @staticmethod
    def _build_native_policy_bundle(plan_json: dict[str, Any]) -> dict[str, Any]:
        """Generate least-privilege policies from the actual Task 3 placements.

        Non-critical discovered edges receive a narrow allow. Critical edges are
        MANUAL_REVIEW by default and only become executable with both approval
        assertions. Existing hand-authored high-priority DENY/obligation policies
        remain authoritative because this bundle uses lower priorities.
        """
        policies: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for placement in plan_json.get("logical_peps", []):
            subject = str(placement.get("subject_canonical_id") or "")
            resource = str(placement.get("resource_canonical_id") or "")
            action = str(placement.get("action") or "")
            workflow = str(placement.get("workflow_id") or "")
            if not subject or not resource or not action:
                continue
            key = (subject, resource, action, workflow, str(placement.get("placement_id") or ""))
            if key in seen:
                continue
            seen.add(key)
            suffix = "".join(
                ch if ch.isalnum() or ch in "._-" else "_"
                for ch in str(placement.get("placement_id") or f"placement_{len(policies)}")
            )
            match: dict[str, Any] = {
                "subjects": [subject],
                "resources": [resource],
                "actions": [action],
            }
            if workflow:
                match["workflows"] = [workflow]

            if bool(placement.get("critical")):
                policies.append(
                    {
                        "id": f"policy.native.{suffix}.pending_review",
                        "description": "Generated native-runtime critical operation gate.",
                        "priority": 280,
                        "effect": "MANUAL_REVIEW",
                        "match": match,
                        "obligations": [],
                        "enabled": True,
                    }
                )
                policies.append(
                    {
                        "id": f"policy.native.{suffix}.approved",
                        "description": "Generated native-runtime approved critical operation.",
                        "priority": 340,
                        "effect": "ALLOW_WITH_OBLIGATIONS",
                        "match": {
                            **match,
                            "approval_valid": True,
                            "secondary_authorization_valid": True,
                        },
                        "obligations": [
                            {"type": "require_idempotency_key", "parameters": {}},
                            {"type": "enhanced_logging", "parameters": {"reason": "native_mas_critical"}},
                        ],
                        "enabled": True,
                    }
                )
            else:
                policies.append(
                    {
                        "id": f"policy.native.{suffix}.allow",
                        "description": "Generated allow for one discovered native MAS edge.",
                        "priority": 120,
                        "effect": "ALLOW_WITH_OBLIGATIONS",
                        "match": match,
                        "obligations": [
                            {"type": "enhanced_logging", "parameters": {"reason": "native_mas_runtime"}}
                        ],
                        "enabled": True,
                    }
                )
        return {
            "apiVersion": "ztb/v1alpha1",
            "kind": "PolicyBundle",
            "metadata": {
                "id": "bundle.native_mas_runtime",
                "version": "1.0.0",
                "domain": "integration",
                "status": "provisional",
            },
            "policies": policies,
        }

    def _prepare_runtime_policy_store(
        self, manifest: dict[str, Any], plan_json: dict[str, Any]
    ) -> Path:
        policy_dir = self.output_dir / "task4_policy_store"
        if policy_dir.exists():
            shutil.rmtree(policy_dir)
        shutil.copytree(self.task4_root / "policy_store", policy_dir)

        # Keep the existing Task 4 intent but bind the EOD update policy to the
        # actual ledger_update_agent discovered in the real MAS.
        subject_ids = {item["id"] for item in manifest["spec"].get("subjects", [])}
        if "agent.back_office.ledger_update" in subject_ids:
            ledger_path = policy_dir / "ledger_access.yaml"
            raw = yaml.safe_load(ledger_path.read_text(encoding="utf-8")) or {}
            changed = False
            for policy in raw.get("policies", []):
                match = policy.get("match", {})
                if (
                    "resource.back_office.ledger" in match.get("resources", [])
                    and "update" in match.get("actions", [])
                    and "agent.back_office.eod" in match.get("subjects", [])
                ):
                    match["subjects"] = ["agent.back_office.ledger_update"]
                    changed = True
            if changed:
                self._write_signed_policy_bundle(self.task4_root, ledger_path, raw)

        native_bundle = self._build_native_policy_bundle(plan_json)
        self._write_signed_policy_bundle(
            self.task4_root, policy_dir / "native_mas_runtime.yaml", native_bundle
        )
        return policy_dir

    def _bootstrap(self) -> None:
        from reconcile import reconcile_task1_task2_to_unified
        from scanner_merge import merge_task2_graph_into_unified
        from native_task4_bridge import NativeTask4InProcessBridge
        from zt_interface.compiler import compile_task4
        from zt_interface.loader import load_yaml
        from zt_interface.validator import validate_manifest as validate_unified_manifest
        from zt_pep.generator import generate_artifacts
        from zt_pep.manifest import validate_manifest as validate_task3_manifest
        from zt_pep.placement import build_pep_plan
        from zt_task5.service import build_task5_components

        task2_output = self.output_dir / "task2" / "draft_manifests"
        reconciled_manifest = self.output_dir / "reconciled_manifest.yaml"
        task3_generated = self.output_dir / "task3_generated"
        task4_config = self.output_dir / "task4_config"

        if self.refresh or not (task2_output / "interaction_edges_draft.yaml").exists():
            task2_output.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [
                    sys.executable,
                    str(self.task2_root / "zt_scan.py"),
                    "--repo-root",
                    str(self.mas_repo_root),
                    "--output-dir",
                    str(task2_output),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )

        reconcile_task1_task2_to_unified(
            self.backplane_root,
            task2_output,
            reconciled_manifest,
            self.output_dir / "task1_task2_reconciliation.json",
        )
        manifest = load_yaml(reconciled_manifest)
        manifest, merge_report = merge_task2_graph_into_unified(
            manifest,
            task2_output,
            banking_repo=self.mas_repo_root,
        )
        manifest = self._augment_native_boundaries(manifest)
        errors = validate_unified_manifest(manifest)
        if errors:
            raise RuntimeError("native unified manifest invalid: " + "; ".join(errors[:8]))
        reconciled_manifest.write_text(
            yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        (self.output_dir / "scanner_graph_merge.json").write_text(
            json.dumps(merge_report, indent=2, sort_keys=True), encoding="utf-8"
        )

        task3_schema = self.task3_root / "interface_contract" / "schemas" / "zt_manifest.schema.json"
        task3_errors = validate_task3_manifest(manifest, task3_schema)
        if task3_errors:
            raise RuntimeError("Task 3 manifest validation failed: " + "; ".join(task3_errors[:8]))
        plan, updated_manifest = build_pep_plan(manifest)
        if task4_config.exists():
            shutil.rmtree(task4_config)
        compile_task4(manifest, task4_config)
        if task3_generated.exists():
            shutil.rmtree(task3_generated)
        generate_artifacts(plan, updated_manifest, task3_generated)
        plan_json = json.loads((task3_generated / "generated_pep_plan.json").read_text(encoding="utf-8"))

        runtime_policy_dir = self._prepare_runtime_policy_store(manifest, plan_json)
        os.environ["ZT_IDENTITY_FILE"] = str(task4_config / "identities.yaml")
        os.environ["ZT_RESOURCE_FILE"] = str(task4_config / "resources.yaml")
        os.environ["ZT_POLICY_DIR"] = str(runtime_policy_dir)
        os.environ["ZT_AUDIT_LOG"] = str(self.output_dir / "task4_decision_log.jsonl")
        os.environ["ZT_POLICY_VERSION_STORE"] = str(self.output_dir / "task4_policy_versions.json")

        from fastapi.testclient import TestClient
        from zt_backplane.pdp_service import build_runtime, create_app

        task4_runtime = build_runtime()
        task4_client = TestClient(create_app(task4_runtime))
        health = task4_client.get("/health")
        if health.status_code >= 400:
            raise RuntimeError(f"Task 4 PDP health failed: {health.text}")

        subject_runtime_ids, resource_runtime_ids = self._build_runtime_maps(manifest)
        bridge = NativeTask4InProcessBridge(
            http_client=task4_client,
            task4_root=self.task4_root,
            subject_runtime_ids=subject_runtime_ids,
            resource_runtime_ids=resource_runtime_ids,
        )
        components = build_task5_components(
            bridge,
            current_policy_version=task4_runtime.engine.bundle.version,
            normal_ttl_seconds=60,
            critical_ttl_seconds=15,
            normal_max_uses=3,
        )

        self.manifest = manifest
        self.plan_json = plan_json
        self.task4_runtime = task4_runtime
        self.task4_client = task4_client
        self.bridge = bridge
        self.components = components
        self.audit_path.write_text("", encoding="utf-8")
        self._write_summary()

    @staticmethod
    def _build_runtime_maps(manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
        environment = manifest["spec"]["defaults"]["environment_binding"]
        subjects: dict[str, str] = {}
        resources: dict[str, str] = {}
        for item in manifest["spec"].get("subjects", []):
            runtime = item.get("bindings", {}).get(environment, {}).get("runtime_id")
            if runtime:
                subjects[item["id"]] = str(runtime)
        for item in manifest["spec"].get("resources", []):
            runtime = item.get("bindings", {}).get(environment, {}).get("runtime_id")
            if runtime:
                resources[item["id"]] = str(runtime)
        return subjects, resources

    def _write_summary(self) -> None:
        coverage = {
            "native_runtime": True,
            "mode": self.mode,
            "logical_pep_count": len(self.plan_json.get("logical_peps", [])),
            "physical_pep_count": len(self.plan_json.get("physical_peps", [])),
            "input_pep_present": self.find_placement_by_id("pep.native.cli_input") is not None,
            "output_pep_present": self.find_placement_by_id("pep.native.cli_output") is not None,
            "policy_version": self.task4_runtime.engine.bundle.version,
        }
        (self.output_dir / "native_runtime_summary.json").write_text(
            json.dumps(coverage, indent=2, sort_keys=True), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # Placement lookups
    # ------------------------------------------------------------------
    def find_placement_by_id(self, placement_id: str) -> dict[str, Any] | None:
        for item in self.plan_json.get("logical_peps", []):
            if str(item.get("placement_id") or "") == placement_id:
                return item
        return None

    def find_input_placement(self) -> dict[str, Any] | None:
        return self.find_placement_by_id("pep.native.cli_input")

    def find_output_placement(self) -> dict[str, Any] | None:
        return self.find_placement_by_id("pep.native.cli_output")

    def find_route_placement(
        self, caller_runtime_id: str, target_runtime_id: str
    ) -> dict[str, Any] | None:
        candidates = []
        for item in self.plan_json.get("logical_peps", []):
            if str(item.get("pep_type") or "") != "agent_route":
                continue
            if str(item.get("subject_runtime_id") or "") != caller_runtime_id:
                continue
            if str(item.get("resource_runtime_id") or "") != target_runtime_id:
                continue
            candidates.append(item)
        if not candidates:
            return None
        return sorted(candidates, key=lambda x: str(x.get("placement_id") or ""))[0]

    def find_tool_placement(
        self,
        agent_runtime_id: str,
        tool_name: str,
        *,
        workflow_id: str | None = None,
    ) -> dict[str, Any] | None:
        scored: list[tuple[int, dict[str, Any]]] = []
        for item in self.plan_json.get("logical_peps", []):
            if str(item.get("subject_runtime_id") or "") != agent_runtime_id:
                continue
            if str(item.get("pep_type") or "") not in {"tool", "mcp", "api", "data"}:
                continue
            score = 0
            interface = str(item.get("interface_id") or "")
            runtime = str(item.get("resource_runtime_id") or "")
            edge_id = str(item.get("edge_id") or "")
            placement_id = str(item.get("placement_id") or "")
            if interface.rsplit(".", 1)[-1] == tool_name:
                score += 100
            if runtime == tool_name:
                score += 80
            if edge_id.endswith("_" + tool_name) or f"_{tool_name}_" in edge_id:
                score += 60
            if placement_id.endswith("." + tool_name) or placement_id.endswith("_" + tool_name):
                score += 40
            item_workflow = str(item.get("workflow_id") or "")
            if workflow_id and item_workflow == workflow_id:
                score += 50
            elif workflow_id and item_workflow and item_workflow != workflow_id:
                score -= 30
            if score > 0:
                scored.append((score, item))
        if not scored:
            return None
        scored.sort(key=lambda pair: (-pair[0], str(pair[1].get("placement_id") or "")))
        return scored[0][1]

    # ------------------------------------------------------------------
    # Runtime PEP / Permit Lease operations
    # ------------------------------------------------------------------
    def _build_pep(self, placement: dict[str, Any]):
        from zt_task5.service import register_generated_pep
        from zt_task5.task3_adapter import Task3PEPAdapter

        physical_id = str(placement["physical_pep_id"])
        if physical_id in self._pep_cache:
            return self._pep_cache[physical_id]
        key = self._pep_keys.setdefault(physical_id, Ed25519PrivateKey.generate())
        pep_identity = f"pep://native-mas/{physical_id}"
        try:
            register_generated_pep(self.components, pep_identity, key)
        except Exception:
            pass
        pep = Task3PEPAdapter(
            self.components.state_machine,
            self.bridge,
            pep_identity=pep_identity,
            pep_private_key=key,
            idempotency_guard=self.components.idempotency_guard,
        )
        self._pep_cache[physical_id] = pep
        return pep

    @staticmethod
    def _obligations(runtime_auth: Any) -> list[Any]:
        if runtime_auth is None:
            return []
        if runtime_auth.validation is not None:
            return list(runtime_auth.validation.obligations or [])
        if runtime_auth.decision is not None:
            return list(runtime_auth.decision.obligations or [])
        return []

    def _request_for(
        self,
        placement: dict[str, Any],
        *,
        parameters: dict[str, Any],
        trace_id: str,
        workflow_instance_id: str,
        workflow_id: str | None = None,
        idempotency_key: str | None = None,
    ):
        from zt_task5.models import UnifiedAuthorizationRequest

        context: dict[str, Any] = {
            "trace_id": trace_id,
            "workflow_instance_id": workflow_instance_id,
            "risk_score": 900 if placement.get("critical") else 350,
            "auth_factors": {"workload_identity": True, "user_session": True},
        }
        if self.human_approval:
            context["with_human_approval"] = True
        if self.secondary_authorization:
            context["with_secondary_authorization"] = True
        if self.change_ticket:
            context["change_ticket"] = self.change_ticket
        return UnifiedAuthorizationRequest(
            subject=str(placement["subject_canonical_id"]),
            resource=str(placement["resource_canonical_id"]),
            action=str(placement["action"]),
            workflow_id=str(workflow_id or placement.get("workflow_id") or ""),
            audience=str(
                placement.get("interface_id")
                or placement.get("physical_pep_id")
                or "native-mas-data-plane"
            ),
            endpoint=str(
                placement.get("interface_id")
                or placement.get("resource_canonical_id")
                or "native-mas"
            ),
            critical=bool(placement.get("critical")),
            risk=str(placement.get("risk") or "low"),
            parameters=dict(parameters),
            context=context,
            idempotency_key=idempotency_key,
        )

    def authorize(
        self,
        placement: dict[str, Any] | None,
        *,
        parameters: dict[str, Any],
        trace_id: str,
        workflow_instance_id: str,
        workflow_id: str | None = None,
        idempotency_key: str | None = None,
        event_type: str,
        caller_runtime_id: str | None = None,
        target_runtime_id: str | None = None,
    ) -> NativeAuthorization:
        started = time.perf_counter_ns()
        if placement is None:
            auth = NativeAuthorization(
                allowed=False,
                would_block=True,
                mode=self.mode,
                reason="NO_GENERATED_PEP_FOR_NATIVE_PATH",
                source="LOCAL_DEFAULT_DENY",
                placement=None,
                request=None,
                runtime_authorization=None,
                authorization_latency_ms=(time.perf_counter_ns() - started) / 1_000_000,
                decision="DENY",
            )
            self._append_audit(
                event_type=event_type,
                auth=auth,
                trace_id=trace_id,
                workflow_instance_id=workflow_instance_id,
                workflow_id=workflow_id or "",
                caller_runtime_id=caller_runtime_id,
                target_runtime_id=target_runtime_id,
                parameters=parameters,
            )
            return auth

        request = self._request_for(
            placement,
            parameters=parameters,
            trace_id=trace_id,
            workflow_instance_id=workflow_instance_id,
            workflow_id=workflow_id,
            idempotency_key=idempotency_key,
        )
        pep = self._build_pep(placement)
        runtime_auth = pep.authorize(request)
        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        decision = None
        policy_version = None
        permit_id = None
        if runtime_auth.decision is not None:
            decision = runtime_auth.decision.decision.value
            policy_version = runtime_auth.decision.policy_version
        if runtime_auth.validation is not None:
            permit_id = runtime_auth.validation.permit_id
        auth = NativeAuthorization(
            allowed=bool(runtime_auth.allowed),
            would_block=not bool(runtime_auth.allowed),
            mode=self.mode,
            reason=str(runtime_auth.reason),
            source=str(runtime_auth.source),
            placement=placement,
            request=request,
            runtime_authorization=runtime_auth,
            authorization_latency_ms=latency_ms,
            permit_id=permit_id,
            policy_version=policy_version,
            decision=decision or ("ALLOW" if runtime_auth.allowed else "DENY"),
        )
        self._append_audit(
            event_type=event_type,
            auth=auth,
            trace_id=trace_id,
            workflow_instance_id=workflow_instance_id,
            workflow_id=request.workflow_id,
            caller_runtime_id=caller_runtime_id,
            target_runtime_id=target_runtime_id,
            parameters=parameters,
        )
        return auth

    def begin_tool(
        self,
        placement: dict[str, Any] | None,
        *,
        tool_args: dict[str, Any],
        trace_id: str,
        workflow_instance_id: str,
        workflow_id: str | None,
        idempotency_key: str,
        caller_runtime_id: str,
        tool_name: str,
    ) -> PendingNativeTool:
        auth = self.authorize(
            placement,
            parameters=tool_args,
            trace_id=trace_id,
            workflow_instance_id=workflow_instance_id,
            workflow_id=workflow_id,
            idempotency_key=idempotency_key,
            event_type="TOOL_AUTHORIZATION",
            caller_runtime_id=caller_runtime_id,
            target_runtime_id=tool_name,
        )
        if placement is None or auth.request is None:
            return PendingNativeTool(auth, None, None, [], False)
        pep = self._build_pep(placement)
        obligations = self._obligations(auth.runtime_authorization)
        if auth.allowed:
            pep._check_pre_obligations(obligations, auth.request)
            pep.idempotency_guard.reserve(
                auth.request.idempotency_key,
                auth.request.request_hash(),
                required=auth.request.critical,
            )
            return PendingNativeTool(auth, pep, auth.request, obligations, True)
        return PendingNativeTool(auth, pep, auth.request, obligations, False)

    def finish_tool(self, pending: PendingNativeTool, result: Any) -> Any:
        if pending.pep is None or pending.request is None:
            return result
        if pending.idempotency_reserved:
            pending.pep.idempotency_guard.commit(pending.request.idempotency_key)
        return self._apply_post_obligations(pending.pep, result, pending.obligations)

    def abort_tool(self, pending: PendingNativeTool | None) -> None:
        if pending and pending.idempotency_reserved and pending.pep is not None:
            pending.pep.idempotency_guard.abort(pending.request.idempotency_key)

    @staticmethod
    def _apply_post_obligations(pep: Any, result: Any, obligations: list[Any]) -> Any:
        """Apply masking to both dict results and ADK's wrapped JSON-string result."""
        direct = pep._apply_post_obligations(result, obligations)
        if direct is not result:
            return direct

        def mask_json_string(value: Any) -> Any:
            if not isinstance(value, str):
                return value
            text = value.strip()
            if not text or text[0] not in "[{":
                return value
            try:
                decoded = json.loads(text)
            except Exception:
                return value
            masked = pep._apply_post_obligations(decoded, obligations)
            if masked == decoded:
                return value
            return json.dumps(masked, ensure_ascii=False)

        if isinstance(result, dict):
            changed = False
            out = dict(result)
            for key, value in list(out.items()):
                masked = mask_json_string(value)
                if masked != value:
                    out[key] = masked
                    changed = True
            return out if changed else result
        return mask_json_string(result)

    def should_execute(self, auth: NativeAuthorization, *, critical: bool = False) -> bool:
        if auth.allowed:
            return True
        if self.mode == "enforce":
            return False
        # Shadow mode may continue non-critical operations. Critical writes remain
        # fail-closed unless explicitly enabled for a controlled benchmark.
        return (not critical) or self.shadow_allow_critical

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_parameter_summary(parameters: Mapping[str, Any]) -> dict[str, Any]:
        raw = json.dumps(parameters, sort_keys=True, default=str).encode("utf-8")
        return {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "keys": sorted(str(k) for k in parameters.keys()),
            "bytes": len(raw),
        }

    def _append_audit(
        self,
        *,
        event_type: str,
        auth: NativeAuthorization,
        trace_id: str,
        workflow_instance_id: str,
        workflow_id: str,
        caller_runtime_id: str | None,
        target_runtime_id: str | None,
        parameters: Mapping[str, Any],
    ) -> None:
        self._audit_seq += 1
        event = {
            "sequence": self._audit_seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "trace_id": trace_id,
            "workflow_instance_id": workflow_instance_id,
            "workflow_id": workflow_id,
            "caller_runtime_id": caller_runtime_id,
            "target_runtime_id": target_runtime_id,
            "placement_id": (
                auth.placement.get("placement_id") if auth.placement is not None else None
            ),
            "physical_pep_id": (
                auth.placement.get("physical_pep_id") if auth.placement is not None else None
            ),
            "decision": auth.decision,
            "allowed": auth.allowed,
            "would_block": auth.would_block,
            "mode": self.mode,
            "reason": auth.reason,
            "source": auth.source,
            "permit_id": auth.permit_id,
            "policy_version": auth.policy_version,
            "authorization_latency_ms": round(auth.authorization_latency_ms, 6),
            "parameter_summary": self._safe_parameter_summary(parameters),
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")

    def append_runtime_event(self, event_type: str, **payload: Any) -> None:
        self._audit_seq += 1
        event = {
            "sequence": self._audit_seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **payload,
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")

    def close(self) -> None:
        try:
            if self.task4_client is not None:
                self.task4_client.close()
        except Exception:
            pass
