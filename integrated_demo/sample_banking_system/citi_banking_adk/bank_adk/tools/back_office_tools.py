def get_eod_batch(batch_id: str):
    """Read an EOD batch."""
    return client.get("/back-office/eod/{batch_id}")


def apply_ledger_updates(batch_id: str):
    """Apply critical ledger updates."""
    return client.post("/back-office/ledger/update")


def store_report(report_id: str):
    """Store a generated report."""
    return client.post("/back-office/reports")
