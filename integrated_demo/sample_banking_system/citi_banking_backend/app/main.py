@app.get("/transactions/{transaction_id}")
def get_transaction(transaction_id: str):
    """Read one transaction."""
    return db.scalar(select(transactions))


@app.post("/banking-api/transfer")
def banking_transfer():
    """Execute transfer."""
    db.add(transfer_record)
    db.commit()
    return {"status": "posted"}


@app.get("/back-office/eod/{batch_id}")
def get_eod_batch(batch_id: str):
    """Read one EOD batch."""
    return db.scalar(select(eod_batches))


@app.post("/back-office/ledger/update")
def ledger_update():
    """Apply ledger update."""
    db.add(ledger_entries)
    db.commit()
    return {"status": "updated"}


@app.post("/back-office/reports")
def store_report():
    """Store a report."""
    db.add(reports)
    db.commit()
    return {"status": "stored"}
