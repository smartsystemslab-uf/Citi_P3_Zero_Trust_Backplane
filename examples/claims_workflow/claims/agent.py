"""Insurance claims desk: an ADK 2.x graph workflow (google.adk.workflow), written without any
knowledge of the Backplane.

    START -> intake_agent -> triage --auto---> pay_claim (tool node) -> notify -> writer_agent
                                     \\-review-> review_flow (nested workflow:            /
                                                 adjuster_agent -> summarize) ----------/
    notify (function node) starts notifier_agent dynamically (ctx.run_node).
"""
from __future__ import annotations

import re

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.events import Event
from google.adk.tools.function_tool import FunctionTool
from google.adk.workflow import START, FunctionNode, Workflow

from . import tools

MODEL = "gemini-2.5-flash"
AUTO_LIMIT = 1000


def triage(node_input) -> Event:
    """Route a claim: small amounts are paid automatically, larger ones go to review."""
    text = str(node_input or "")
    claim = re.search(r"claim (C-\d+)", text)
    amount = re.search(r"amount (\d+)", text)
    claim_id = claim.group(1) if claim else "C-0"
    value = int(amount.group(1)) if amount else 0
    route = "auto" if value <= AUTO_LIMIT else "review"
    return Event(route=route, output={"claim_id": claim_id, "amount": value})


def summarize(node_input) -> str:
    """Summarise the adjuster's review."""
    return f"review: {node_input}"


notifier_agent = LlmAgent(name="notifier_agent", model=MODEL, instruction="Tell the policy holder about the payout.")


async def notify(ctx, node_input) -> str:
    """Notify the policy holder (an agent started dynamically)."""
    told = await ctx.run_node(notifier_agent, node_input=f"payout {node_input}")
    return f"notified: {told}"


def build_root() -> Workflow:
    intake_agent = LlmAgent(name="intake_agent", model=MODEL, instruction="Collect the claim details.",
                            tools=[tools.lookup_policy])
    adjuster_agent = LlmAgent(name="adjuster_agent", model=MODEL, instruction="Review the claim.",
                              tools=[tools.read_claim_history])
    writer_agent = LlmAgent(name="writer_agent", model=MODEL, instruction="Write the final answer.")
    pay = FunctionTool(tools.pay_claim)
    review_flow = Workflow(name="review_flow", edges=[(START, adjuster_agent, FunctionNode(func=summarize))])
    return Workflow(name="claims_desk", edges=[
        (START, intake_agent, FunctionNode(func=triage), {"auto": pay, "review": review_flow}),
        (pay, FunctionNode(func=notify, rerun_on_resume=True), writer_agent),
        (review_flow, writer_agent),
    ])


root_agent = build_root()
app = App(name="claims", root_agent=root_agent)
