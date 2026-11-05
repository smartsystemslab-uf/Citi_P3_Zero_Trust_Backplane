# Static-analysis fixture for Task 2. It is intentionally not executed.
eod_processing_agent = LlmAgent(
    name="eod_processing_agent",
    description="Coordinate end-of-day processing.",
    tools=[get_eod_batch, apply_ledger_updates, store_report],
)

report_writing_agent = LlmAgent(
    name="report_writing_agent",
    description="Write end-of-day reports.",
    tools=[store_report],
)
