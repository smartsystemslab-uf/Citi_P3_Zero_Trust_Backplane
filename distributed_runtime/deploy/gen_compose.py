"""Generate deploy/compose.yaml from zt_distributed/catalog.py (host-side, stdlib only).

JSON is valid YAML, so the output is plain JSON. Every workload gets its own container,
hostname, UID and `org.citi-p3.ztbp.workload` label, the SPIRE Workload API socket
(read-only) and ONLY its own secret sub-path. Only compose project `citi_p3_ztbp` is used.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # distributed_runtime/
sys.path.insert(0, str(ROOT))
from zt_distributed import catalog  # noqa: E402

P = catalog.CONTAINER_PREFIX
RUNTIME_IMAGE = "citi-ztbp/runtime:dev"
BACKEND_IMAGE = "citi-ztbp/backend:dev"
SPIRE_IMAGE = "citi-ztbp/spire:1.15.3"
BP = "/opt/citi/Citi_P3_Zero_Trust_Backplane/zero_trust_pdp_task4_secure"
NET = "ztbp"
LIMITS = {
    "spire-server": ("1.0", "512m"), "spire-agent": ("1.0", "512m"),
    "zt-gateway": ("2.0", "2g"), "bank-backend": ("1.0", "1g"), "agent-issuer": ("1.0", "512m"),
    "ingress-client": ("1.0", "512m"), "agent": ("1.0", "1g"),
}


def secret(subpath: str, target: str) -> dict:
    return {"type": "volume", "source": "secrets", "target": target, "read_only": True,
            "volume": {"subpath": subpath, "nocopy": True}}


def runtime_env(extra: dict) -> dict:
    env = {
        "SPIFFE_ENDPOINT_SOCKET": "unix:///run/spire/sockets/agent.sock",
        "CITI_TRUST_DOMAIN": catalog.TRUST_DOMAIN,
        "CONN_MODE": "${CONN_MODE:-reuse}",
        "TLS_SESSION_TICKETS": "${TLS_SESSION_TICKETS:-on}",
        "AGENT_RENEW_FRACTION": "${AGENT_RENEW_FRACTION:-0.5}",
        "HOME": "/tmp",
        "BANKING_ADK_RUNTIME_DIR": "/tmp/bankadk-unused",
        "BANKING_BACKEND_BASE_URL": catalog.BACKEND_URL,
        "BANKING_USE_EXTERNAL_API": "true",
    }
    env.update(extra)
    return env


def service(name: str, *, uid: int, command: list[str], env: dict, volumes: list, limits: tuple[str, str]) -> dict:
    return {
        "image": RUNTIME_IMAGE,
        "container_name": f"{P}{name}",
        "hostname": name,
        "user": f"{uid}:{uid}",
        "labels": {catalog.LABEL_KEY: name},
        "networks": [NET],
        "environment": env,
        "command": command,
        "volumes": volumes,
        "cpus": limits[0],
        "mem_limit": limits[1],
        "stop_grace_period": "5s",
        "init": True,
    }


def main() -> None:
    live = "/results/live"
    common_vols = ["spire-sockets:/run/spire/sockets:ro", "../results:/results"]
    services: dict[str, dict] = {}
    services["spire-server"] = {
        "image": SPIRE_IMAGE, "container_name": f"{P}spire-server", "hostname": "spire-server",
        "networks": [NET], "command": ["spire-server", "run", "-config", "/etc/spire/server.conf"],
        "volumes": ["./spire/server.conf:/etc/spire/server.conf:ro",
                    "../runtime/public/spire/node_ca.pem:/etc/spire/node_ca.pem:ro",
                    "../runtime/public/spire/entries.json:/etc/spire/entries.json:ro",
                    "./spire/register.py:/opt/register.py:ro",
                    "spire-server-data:/var/lib/spire/server"],
        "cpus": LIMITS["spire-server"][0], "mem_limit": LIMITS["spire-server"][1],
        "labels": {catalog.LABEL_KEY: "spire-server"},
    }
    services["spire-agent"] = {
        "image": SPIRE_IMAGE, "container_name": f"{P}spire-agent", "hostname": "spire-agent",
        "networks": [NET], "pid": "host",
        "command": ["spire-agent", "run", "-config", "/etc/spire/agent.conf"],
        "volumes": ["./spire/agent.conf:/etc/spire/agent.conf:ro",
                    "../runtime/public/spire/bootstrap_bundle.pem:/etc/spire/bootstrap_bundle.pem:ro",
                    "/var/run/docker.sock:/var/run/docker.sock:ro",
                    "spire-sockets:/run/spire/sockets",
                    "spire-agent-data:/var/lib/spire/agent",
                    secret("spire-node", "/run/secrets/spire-node")],
        "cpus": LIMITS["spire-agent"][0], "mem_limit": LIMITS["spire-agent"][1],
        "labels": {catalog.LABEL_KEY: "spire-agent"},
    }
    services["bank-backend"] = {
        "image": BACKEND_IMAGE, "container_name": f"{P}bank-backend", "hostname": "bank-backend",
        "networks": [NET], "user": "20010:20010",
        "environment": {"DATABASE_URL": "sqlite:////var/lib/bank/citi_banking.db", "HOME": "/tmp"},
        "volumes": ["bankdata:/var/lib/bank"],
        "cpus": LIMITS["bank-backend"][0], "mem_limit": LIMITS["bank-backend"][1], "init": True,
        "labels": {catalog.LABEL_KEY: "bank-backend"},
    }
    gw = catalog.SERVICES["zt-gateway"]
    services["zt-gateway"] = service(
        "zt-gateway", uid=gw.uid, command=["python", "-m", "zt_distributed.gateway"],
        env=runtime_env({"BANKING_ADK_RUNTIME_DIR": "/var/lib/bankadk",
                         "CITI_EVENTS_FILE": f"{live}/zt-gateway.events.jsonl",
                         "CITI_SPANS_FILE": f"{live}/zt-gateway.spans.jsonl",
                         "CITI_COMPONENT": "zt-gateway"}),
        volumes=common_vols + [
            "bankadk:/var/lib/bankadk", "gwout:/var/lib/zt-gateway",
            secret("task4-keys", f"{BP}/security/dev_keys"),
            f"../runtime/public/task4/policy_store:{BP}/policy_store:ro",
            "../runtime/public/config:/etc/citi/config:ro",
            "../runtime/public/agent-ca:/etc/citi/agent-ca:ro",
        ],
        limits=LIMITS["zt-gateway"])
    iss = catalog.SERVICES["agent-issuer"]
    services["agent-issuer"] = service(
        "agent-issuer", uid=iss.uid, command=["python", "-m", "zt_identity.agent_identity.issuer"],
        env=runtime_env({"AGENT_CERT_TTL_SECONDS": "${AGENT_CERT_TTL_SECONDS:-86400}",
                         "GATEWAY_SPIFFE_ID": gw.spiffe_id,
                         "CITI_EVENTS_FILE": f"{live}/agent-issuer.events.jsonl", "CITI_COMPONENT": "agent-issuer"}),
        volumes=common_vols + ["issuer-state:/var/lib/agent-issuer",
                               secret("agent-ca", "/run/secrets/agent-ca"),
                               "../runtime/public/config:/etc/citi/config:ro",
                               "../runtime/public/agent-ca:/etc/citi/agent-ca:ro"],
        limits=LIMITS["agent-issuer"])
    ic = catalog.SERVICES["ingress-client"]
    services["ingress-client"] = service(
        "ingress-client", uid=ic.uid, command=["sleep", "infinity"],
        env=runtime_env({"CITI_COMPONENT": "ingress-client"}), volumes=common_vols,
        limits=LIMITS["ingress-client"])
    for agent_id, w in catalog.AGENTS.items():
        services[w.name] = service(
            w.name, uid=w.uid, command=["python", "-m", "zt_distributed.agent_service"],
            env=runtime_env({"AGENT_ID": agent_id, "CITI_COMPONENT": w.name,
                             "CITI_EVENTS_FILE": f"{live}/{w.name}.events.jsonl",
                             "CITI_SPANS_FILE": f"{live}/{w.name}.spans.jsonl"}),
            volumes=common_vols + [secret(f"agents/{agent_id}", "/run/secrets/agent-enroll")],
            limits=LIMITS["agent"])
    # one-shot helpers for prepare / reset / verification (root; never serve traffic)
    services["ops"] = {
        "image": RUNTIME_IMAGE, "container_name": f"{P}ops", "profiles": ["ops"], "networks": [NET],
        "user": "0:0", "command": ["true"],
        "environment": {"HOME": "/tmp", "BANKING_ADK_RUNTIME_DIR": "/tmp/bankadk-unused"},
        "volumes": ["secrets:/secrets", "golden:/golden", "bankadk:/var/lib/bankadk", "bankdata:/var/lib/bank",
                    "gwout:/var/lib/zt-gateway", "issuer-state:/var/lib/agent-issuer",
                    "../runtime/public:/public", "../results:/results"],
    }
    services["ops-backend"] = {
        "image": BACKEND_IMAGE, "container_name": f"{P}ops-backend", "profiles": ["ops"],
        "user": "0:0", "command": ["true"], "networks": [NET],
        "volumes": ["golden:/golden", "../runtime/public:/public"],
    }
    compose = {
        "name": catalog.COMPOSE_PROJECT,
        "services": services,
        "networks": {NET: {"driver": "bridge"}},
        "volumes": {v: {} for v in ["spire-server-data", "spire-agent-data", "spire-sockets", "secrets", "golden",
                                    "bankadk", "bankdata", "gwout", "issuer-state"]},
    }
    out = ROOT / "deploy" / "compose.yaml"
    out.write_text("# GENERATED by deploy/gen_compose.py from zt_distributed/catalog.py - do not edit\n"
                   + json.dumps(compose, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out} with {len(services)} services")


if __name__ == "__main__":
    main()
