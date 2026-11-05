# Static-analysis fixture for Task 2. It is intentionally not executed.
fraud_detection_agent = LlmAgent(
    name="fraud_detection_agent",
    description="Review suspicious transactions.",
    tools=[get_transaction_context, search_policies],
)

transaction_processing_agent = LlmAgent(
    name="transaction_processing_agent",
    description="Execute approved customer transactions.",
    tools=[execute_transfer],
)

compliance_agent = LlmAgent(
    name="compliance_agent",
    description="Retrieve policy guidance.",
    tools=[search_policies],
)
