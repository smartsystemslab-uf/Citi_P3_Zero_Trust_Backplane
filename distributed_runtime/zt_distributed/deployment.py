"""Deployment descriptor of the distributed runtime (one container per agent).

Generated from the protected application itself (``describe``: discovery of the live ADK
tree inside the runtime image) and its ``zt_adk.yaml`` profile. Every other part of the
deployment -- compose file, SPIRE registrations, agent registry, service map, the gateway's
upstream map and the workloads' own identity -- reads this one file
(``/etc/zt/deployment.json`` in the containers, ``runtime/deployment.json`` on the host).

Identities (SPIFFE scheme B):
  spiffe://<trust domain>/ztbp/wl/<agent>     the workload of one agent
  spiffe://<trust domain>/ztbp/svc/<service>  gateway, agent-credential issuer, ingress
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PATH = Path(os.environ.get("ZT_DEPLOYMENT", "/etc/zt/deployment.json"))
GATEWAY_PORT = 8443
AGENT_PORT = 9443
ISSUER_PORT = 8444
OPS_PORT = 9901          # local-only health/stats listener inside each container
LABEL_KEY = "org.zt-adk.workload"
INGRESS_AGENT_ID = "ingress"


def dns_name(text: str, prefix: str = "") -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", text).lower()).strip("-")
    s = (prefix + s)[:63].rstrip("-")
    return s or "x"


@dataclass(frozen=True)
class Workload:
    name: str                       # container / compose service / host name / label value
    uid: int
    spiffe_id: str
    kind: str                       # agent | service
    agent_id: str | None = None
    adk_kind: str | None = None     # llm | sequential | parallel | loop | custom | remote
    user_roles: tuple[str, ...] = ()


@dataclass
class Deployment:
    app_name: str
    root_agent: str
    trust_domain: str
    compose_project: str
    container_prefix: str
    fingerprint: str
    agents: dict[str, Workload]
    services: dict[str, Workload]
    entry_agents: list[str] = field(default_factory=list)
    user_services: list[dict[str, Any]] = field(default_factory=list)
    model_override: dict[str, Any] | None = None

    # -- identities -------------------------------------------------------------------
    def wl_spiffe(self, agent_id: str) -> str:
        return f"spiffe://{self.trust_domain}/ztbp/wl/{agent_id}"

    def svc_spiffe(self, name: str) -> str:
        return f"spiffe://{self.trust_domain}/ztbp/svc/{name}"

    @property
    def node_alias(self) -> str:
        return f"spiffe://{self.trust_domain}/spire/agent/x509pop/node-1"

    def selectors(self, w: Workload) -> list[str]:
        """SPIRE selectors: deployment label + compose project + distinct UID."""
        return [f"docker:label:{LABEL_KEY}:{w.name}",
                f"docker:label:com.docker.compose.project:{self.compose_project}",
                f"unix:uid:{w.uid}"]

    # -- addresses --------------------------------------------------------------------
    @property
    def gateway(self) -> Workload:
        return self.services["zt-gateway"]

    @property
    def issuer(self) -> Workload:
        return self.services["agent-issuer"]

    @property
    def ingress(self) -> Workload:
        return self.services["ingress-client"]

    def gateway_authority(self) -> str:
        return f"zt-gateway:{GATEWAY_PORT}"

    def gateway_url(self) -> str:
        return f"https://{self.gateway_authority()}"

    def issuer_url(self) -> str:
        return f"https://agent-issuer:{ISSUER_PORT}"

    def agent_url(self, agent_id: str) -> str:
        return f"https://{self.agents[agent_id].name}:{AGENT_PORT}"

    def workload_by_name(self, name: str) -> Workload:
        for w in list(self.services.values()) + list(self.agents.values()):
            if w.name == name:
                return w
        raise KeyError(name)

    # -- (de)serialisation -------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Deployment":
        def wl(x: dict[str, Any]) -> Workload:
            return Workload(**{**x, "user_roles": tuple(x.get("user_roles") or ())})

        return cls(app_name=raw["app_name"], root_agent=raw["root_agent"], trust_domain=raw["trust_domain"],
                   compose_project=raw["compose_project"], container_prefix=raw["container_prefix"],
                   fingerprint=raw["fingerprint"], agents={k: wl(v) for k, v in raw["agents"].items()},
                   services={k: wl(v) for k, v in raw["services"].items()},
                   entry_agents=list(raw.get("entry_agents") or []),
                   user_services=list(raw.get("user_services") or []),
                   model_override=raw.get("model_override"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=1, sort_keys=True) + "\n", encoding="utf-8")


_CACHE: Deployment | None = None


def load(path: Path | None = None) -> Deployment:
    global _CACHE
    if path is None and _CACHE is not None:
        return _CACHE
    p = Path(path or DEFAULT_PATH)
    dep = Deployment.from_dict(json.loads(p.read_text(encoding="utf-8")))
    if path is None:
        _CACHE = dep
    return dep


def describe(model: Any, profile: Any) -> Deployment:
    """Deployment of a discovered system model under a profile."""
    from zt_adk import model as M

    td = profile.identity.trust_domain
    dist = profile.distributed
    services = {
        "zt-gateway": Workload("zt-gateway", 20001, f"spiffe://{td}/ztbp/svc/zt-gateway", "service"),
        "agent-issuer": Workload("agent-issuer", 20002, f"spiffe://{td}/ztbp/svc/agent-issuer", "service"),
        "ingress-client": Workload("ingress-client", 20003, f"spiffe://{td}/ztbp/svc/ingress", "service",
                                   agent_id=INGRESS_AGENT_ID,
                                   user_roles=tuple(profile.session.roles or [])),
    }
    agents: dict[str, Workload] = {}
    used: set[str] = set(services)
    for i, name in enumerate(sorted(model.agents)):
        host = dns_name(name, "wl-")
        n = 2
        while host in used:
            host = dns_name(f"{name}-{n}", "wl-")
            n += 1
        used.add(host)
        agents[name] = Workload(host, 21001 + i, f"spiffe://{td}/ztbp/wl/{name}", "agent", agent_id=name,
                                adk_kind=model.agents[name].kind)
    entries = sorted({e.target for e in model.edges if e.kind == M.EDGE_ENTRY})
    return Deployment(
        app_name=model.app_name, root_agent=model.root_agent, trust_domain=td,
        compose_project=dist.compose_project, container_prefix=dist.container_prefix,
        fingerprint=model.fingerprint(), agents=agents, services=services, entry_agents=entries,
        user_services=[s.model_dump() for s in dist.services],
        model_override=profile.model_override.model_dump() if profile.model_override else None)
