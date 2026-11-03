"""Single source of truth for the distributed runtime's workloads and identities.

Every logical agent runs in its own container ("workload") with its own UID, its own
Docker label and its own SPIFFE ID (SPIFFE scheme B: the agent additionally holds an
agent certificate bound to that workload SVID). SPIRE registrations, the compose file,
the controlled service map and the agent registry are all generated from this module.
"""
from __future__ import annotations

from dataclasses import dataclass

TRUST_DOMAIN = "citi-p3.test"
COMPOSE_PROJECT = "citi_p3_ztbp"
CONTAINER_PREFIX = "ztbp-"
LABEL_KEY = "org.citi-p3.ztbp.workload"
NODE_ALIAS = f"spiffe://{TRUST_DOMAIN}/spire/agent/x509pop/node-1"

GATEWAY_HOST = "zt-gateway"
GATEWAY_PORT = 8443
GATEWAY_AUTHORITY = f"{GATEWAY_HOST}:{GATEWAY_PORT}"
AGENT_PORT = 9443
ISSUER_HOST = "agent-issuer"
ISSUER_PORT = 8444
BACKEND_URL = "http://bank-backend:8000"
OPS_PORT = 9901                      # local-only health/stats listener inside each container

# End-user roles of the Task 1 intent rule intent.require-valid-session.
USER_ROLES = ("customer", "internal_rep", "ops_scheduler", "system", "auditor")


def wl_spiffe(agent_id: str) -> str:
    return f"spiffe://{TRUST_DOMAIN}/ztbp/wl/{agent_id}"


def svc_spiffe(name: str) -> str:
    return f"spiffe://{TRUST_DOMAIN}/ztbp/svc/{name}"


@dataclass(frozen=True)
class Workload:
    name: str            # container / compose service / label value
    uid: int
    spiffe_id: str
    kind: str            # "agent" | "service"
    agent_id: str | None = None
    orchestrator: bool = False
    # ingress services only: end-user roles this front end may assert for a session
    user_roles: tuple[str, ...] = ()


SERVICES = {
    "zt-gateway": Workload("zt-gateway", 20001, svc_spiffe("zt-gateway"), "service"),
    "agent-issuer": Workload("agent-issuer", 20002, svc_spiffe("agent-issuer"), "service"),
    # the trusted front end: authenticates end users and asserts their session/role
    "ingress-client": Workload("ingress-client", 20003, svc_spiffe("cli-ingress"), "service",
                               agent_id="cli_user", user_roles=USER_ROLES),
}

# Logical agents of the integration scenarios (original ADK agents).
_BASE_AGENTS = [
    ("transaction_monitoring_agent", "wl-transaction-monitoring", False),   # read
    ("transaction_processing_agent", "wl-transaction-processing", False),   # critical write
    ("back_office_eod_workflow", "wl-eod-workflow", True),                  # EOD orchestrator
    ("validation_checkpoint_agent", "wl-validation-checkpoint", False),
    ("eod_processing_agent", "wl-eod-processing", False),
    ("ledger_update_agent", "wl-ledger-update", False),
    ("reconciliation_agent", "wl-reconciliation", False),
    ("report_writing_agent", "wl-report-writing", False),
    ("exception_agent", "wl-exception", False),
    # customer-service chatbot workflow: the legitimate path to execute_transfer
    # (intent.execute-transfer-caller-restriction.order needs the customer-service step first)
    ("customer_service_chatbot_workflow", "wl-chatbot-workflow", True),     # chatbot orchestrator
    ("chatbot_intent_agent", "wl-chatbot-intent", False),
    ("customer_service_agent", "wl-customer-service", False),
    ("knowledge_base_agent", "wl-knowledge-base", False),
]
AGENTS: dict[str, Workload] = {
    agent_id: Workload(host, 21001 + i, wl_spiffe(agent_id), "agent", agent_id=agent_id, orchestrator=orch)
    for i, (agent_id, host, orch) in enumerate(_BASE_AGENTS)
}

# Children each orchestrator invokes (fields of the original BackOfficeEodWorkflowAgent and
# CustomerServiceChatbotWorkflowAgent); every child runs in its own workload.
ORCHESTRATOR_CHILDREN = {
    "back_office_eod_workflow": {
        "validation_agent": "validation_checkpoint_agent",
        "processing_agent": "eod_processing_agent",
        "ledger_update_agent": "ledger_update_agent",
        "reconciliation_agent": "reconciliation_agent",
        "report_agent": "report_writing_agent",
        "exception_agent": "exception_agent",
    },
    "customer_service_chatbot_workflow": {
        "intent_agent": "chatbot_intent_agent",
        "knowledge_agent": "knowledge_base_agent",
        "service_agent": "customer_service_agent",
        "processing_agent": "transaction_processing_agent",
    },
}


def workload_by_name(name: str) -> Workload:
    for w in list(SERVICES.values()) + list(AGENTS.values()):
        if w.name == name:
            return w
    raise KeyError(name)


def agent_url(agent_id: str) -> str:
    return f"https://{AGENTS[agent_id].name}:{AGENT_PORT}"


def gateway_url() -> str:
    return f"https://{GATEWAY_AUTHORITY}"


def issuer_url() -> str:
    return f"https://{ISSUER_HOST}:{ISSUER_PORT}"


def selectors(w: Workload) -> list[str]:
    """SPIRE selectors: deployment label + compose project + distinct UID."""
    return [
        f"docker:label:{LABEL_KEY}:{w.name}",
        f"docker:label:com.docker.compose.project:{COMPOSE_PROJECT}",
        f"unix:uid:{w.uid}",
    ]
