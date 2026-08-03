# Logical-to-Physical PEP Map

## `physical_pep.data_enforce_closed_shared_data_access_guard`
- Type: `data`
- Generated adapter: `adapters/data_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.eod_processing.reconcile`
  - `pep.fraud_review.read_history`

## `physical_pep.event_enforce_closed_mcp`
- Type: `event`
- Generated adapter: `adapters/event_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.eod_processing.get_batches`

## `physical_pep.mcp_enforce_closed_shared_mcp_gateway`
- Type: `mcp`
- Generated adapter: `adapters/mcp_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.customer_transaction.execute_transfer`
  - `pep.customer_transaction.get_context`
  - `pep.eod_processing.create_exception`
  - `pep.eod_processing.ledger_update`
  - `pep.eod_processing.store_report`
  - `pep.eod_processing.write_report`
  - `pep.fraud_review.search_policies`
