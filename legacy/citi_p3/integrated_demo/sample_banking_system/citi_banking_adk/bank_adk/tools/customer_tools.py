def get_transaction_context(transaction_id: str):
    """Read transaction context."""
    return client.get("/transactions/{transaction_id}")


def execute_transfer(account_from: str, account_to: str, amount: float):
    """Execute a banking transfer."""
    return client.post("/banking-api/transfer")
