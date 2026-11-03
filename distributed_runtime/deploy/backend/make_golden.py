"""Golden synthetic dataset for the original citi_banking_backend.

Runs the backend's own init_db(seed=True) (original schema + original demo
seed), then adds deterministic synthetic customers/accounts/transactions so
that every write request in a run can use a distinct source account and every
read targets a distinct customer (no customer data is copied from anywhere).
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/golden/backend.db")
    ap.add_argument("--customers", type=int, default=20000)
    ap.add_argument("--destinations", type=int, default=1000)
    ns = ap.parse_args()
    if os.path.exists(ns.out):
        os.unlink(ns.out)
    os.environ["DATABASE_URL"] = f"sqlite:///{ns.out}"
    sys.path.insert(0, "/opt/citi/citi_banking_backend")
    from app.seed import init_db  # original backend code

    init_db(seed=True)
    old = (datetime.utcnow() - timedelta(days=3)).isoformat(sep=" ")
    now = datetime.utcnow().isoformat(sep=" ")
    conn = sqlite3.connect(ns.out)
    cust, acct, txs = [], [], []
    for i in range(ns.customers):
        cid = f"CUST-B{i:05d}"
        cust.append((cid, f"Synthetic Customer {i:05d}", f"synthetic{i:05d}@example.invalid", "000-000-0000",
                     "Synthetic", "verified", "low", now))
        acct.append((f"ACC-B{i:05d}", cid, "checking", 50000.0, "USD", "active", now))
        for k in ("A", "B"):
            txs.append((f"TXN-B{i:05d}-{k}", f"ACC-B{i:05d}", f"ACC-D{i % ns.destinations:05d}",
                        100.0 + (i % 500), "USD", "transfer", "completed", 10, "synthetic history", old))
    for j in range(ns.destinations):
        acct.append((f"ACC-D{j:05d}", "CUST-EXT", "checking", 0.0, "USD", "active", now))
    conn.executemany("INSERT INTO customers (customer_id, full_name, email, phone, address, kyc_status, risk_level, created_at) "
                     "VALUES (?,?,?,?,?,?,?,?)", cust)
    conn.executemany("INSERT INTO accounts (account_id, customer_id, account_type, balance, currency, status, created_at) "
                     "VALUES (?,?,?,?,?,?,?)", acct)
    conn.executemany("INSERT INTO transactions (transaction_id, from_account_id, to_account_id, amount, currency, tx_type, "
                     "status, risk_score, decision_reason, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", txs)
    conn.commit()
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.close()
    os.chmod(ns.out, 0o644)
    print(f"backend golden: {ns.customers} customers, {len(acct)} accounts, {len(txs)} synthetic transactions")


if __name__ == "__main__":
    main()
