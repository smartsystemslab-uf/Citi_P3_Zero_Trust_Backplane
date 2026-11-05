"""Example ADK multi-agent system: an IT service desk.

Uses every composition form ADK offers, so it doubles as the acceptance target of the
Zero Trust Backplane:

  service_desk (LlmAgent, root)               LLM transfer to its sub-agents
  |-- account_agent (LlmAgent)                lookup_user, unlock_account, reset_password,
  |                                           request_hardware (long-running)
  |-- triage_agent (LlmAgent)                 search_kb, AgentTool(web_research_agent)
  |       web_research_agent (LlmAgent)       google_search (model-side built-in)
  `-- incident_workflow (SequentialAgent)
        |-- intake_agent (LlmAgent)           create_ticket
        |-- context_gatherer (ParallelAgent)
        |     |-- asset_agent (LlmAgent)      get_asset (FunctionTool)
        |     `-- history_agent (LlmAgent)    get_ticket_history
        |-- diagnosis_loop (LoopAgent)
        |     |-- diagnostic_agent (LlmAgent) run_diagnostic
        |     `-- escalation_checker (custom BaseAgent: ends the loop)
        `-- resolution_agent (LlmAgent)       update_ticket, notify_user

The model is "gemini-2.5-flash" (GOOGLE_API_KEY or Vertex AI settings in the environment).
"""
from __future__ import annotations

from typing import AsyncGenerator

from google.adk.agents import BaseAgent, LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.apps import App
from google.adk.events import Event, EventActions
from google.adk.tools import google_search
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.long_running_tool import LongRunningFunctionTool

from . import tools

MODEL = "gemini-2.5-flash"


class EscalationChecker(BaseAgent):
    """Ends the diagnosis loop once the last diagnostic resolved the problem."""

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        resolved = ctx.session.state.get("diagnosis_status") == "resolved"
        yield Event(author=self.name, invocation_id=ctx.invocation_id, branch=ctx.branch,
                    actions=EventActions(escalate=resolved))


def build_root_agent() -> LlmAgent:
    web_research_agent = LlmAgent(
        name="web_research_agent", model=MODEL,
        description="Searches the public web for vendor documentation.",
        instruction="Search the web and summarise the vendor's official guidance in three sentences.",
        tools=[google_search])
    account_agent = LlmAgent(
        name="account_agent", model=MODEL,
        description="Handles user accounts: lookups, unlocks, password resets, hardware requests.",
        instruction="Help with the user's account. Use the tools; never reveal a password.",
        tools=[tools.lookup_user, tools.unlock_account, tools.reset_password,
               LongRunningFunctionTool(func=tools.request_hardware)])
    triage_agent = LlmAgent(
        name="triage_agent", model=MODEL,
        description="Answers how-to questions from the knowledge base and vendor documentation.",
        instruction="Answer from the knowledge base first; use web_research_agent for vendor documentation.",
        tools=[tools.search_kb, AgentTool(agent=web_research_agent)])
    intake_agent = LlmAgent(
        name="intake_agent", model=MODEL, description="Opens the incident ticket.",
        instruction="Open a ticket for the reported incident with create_ticket.",
        tools=[tools.create_ticket], output_key="intake_summary")
    asset_agent = LlmAgent(
        name="asset_agent", model=MODEL, description="Collects the user's assets.",
        instruction="List the assets of {ticket_user?}.", tools=[FunctionTool(func=tools.get_asset)],
        output_key="assets_summary")
    history_agent = LlmAgent(
        name="history_agent", model=MODEL, description="Collects the user's ticket history.",
        instruction="List the earlier tickets of {ticket_user?}.", tools=[tools.get_ticket_history],
        output_key="history_summary")
    diagnostic_agent = LlmAgent(
        name="diagnostic_agent", model=MODEL, description="Runs diagnostics on the affected asset.",
        instruction="Run one diagnostic check on the affected asset.", tools=[tools.run_diagnostic])
    resolution_agent = LlmAgent(
        name="resolution_agent", model=MODEL, description="Closes the ticket and informs the user.",
        instruction="Update ticket {ticket_id?} and notify {ticket_user?}.",
        tools=[tools.update_ticket, tools.notify_user])
    incident_workflow = SequentialAgent(
        name="incident_workflow", description="Handles a reported incident end to end.",
        sub_agents=[
            intake_agent,
            ParallelAgent(name="context_gatherer", sub_agents=[asset_agent, history_agent]),
            LoopAgent(name="diagnosis_loop", max_iterations=3,
                      sub_agents=[diagnostic_agent, EscalationChecker(name="escalation_checker")]),
            resolution_agent,
        ])
    return LlmAgent(
        name="service_desk", model=MODEL,
        description="IT service desk front door.",
        instruction=("Route the request: accounts and passwords to account_agent, questions to triage_agent, "
                     "reported incidents to incident_workflow."),
        sub_agents=[account_agent, triage_agent, incident_workflow])


root_agent = build_root_agent()
app = App(name="helpdesk", root_agent=root_agent)
