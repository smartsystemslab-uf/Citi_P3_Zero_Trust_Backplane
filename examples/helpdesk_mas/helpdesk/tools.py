"""Tools of the example IT service desk. Every tool reads or changes the SQLite store."""
from __future__ import annotations

import hashlib
import secrets
import subprocess
import sys

from google.adk.tools.tool_context import ToolContext

from . import store


def lookup_user(username: str) -> dict:
    """Look up a user account: name, e-mail, department and whether the account is locked."""
    with store.connect() as conn:
        row = conn.execute("SELECT username, full_name, email, department, locked FROM users WHERE username = ?",
                           (username,)).fetchone()
    if row is None:
        return {"status": "not_found", "username": username}
    return {"status": "ok", "user": store.as_json(row)}


def unlock_account(username: str, reason: str) -> dict:
    """Unlock a locked user account."""
    with store.connect() as conn:
        cur = conn.execute("UPDATE users SET locked = 0 WHERE username = ?", (username,))
        conn.commit()
    return {"status": "ok" if cur.rowcount else "not_found", "username": username, "reason": reason}


def reset_password(username: str) -> dict:
    """Reset a user's password and issue a one-time temporary password."""
    temporary = secrets.token_urlsafe(9)
    with store.connect() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ? WHERE username = ?",
            (hashlib.sha256(temporary.encode()).hexdigest(), store.now(), username))
        conn.commit()
    if not cur.rowcount:
        return {"status": "not_found", "username": username}
    return {"status": "ok", "username": username, "temporary_password_issued": True}


def request_hardware(username: str, item: str) -> dict:
    """Request new hardware for a user. The request needs a manager decision, which arrives later."""
    request_id = store.new_id("HW")
    with store.connect() as conn:
        conn.execute("INSERT INTO hardware_requests VALUES (?, ?, ?, ?, ?)",
                     (request_id, username, item, "pending_manager", store.now()))
        conn.commit()
    return {"status": "pending", "request_id": request_id}


def search_kb(query: str) -> dict:
    """Search the knowledge base for articles that match the query."""
    words = [w for w in query.lower().split() if len(w) > 2]
    with store.connect() as conn:
        rows = conn.execute("SELECT article_id, title, body FROM kb_articles").fetchall()
    hits = [store.as_json(r) for r in rows if any(w in (r["title"] + " " + r["body"]).lower() for w in words)]
    return {"status": "ok", "articles": hits[:5]}


def create_ticket(username: str, summary: str, priority: str, tool_context: ToolContext) -> dict:
    """Open an incident ticket for a user."""
    ticket_id = store.new_id("INC")
    with store.connect() as conn:
        conn.execute("INSERT INTO tickets (ticket_id, username, summary, status, priority, created_at, updated_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (ticket_id, username, summary, "open", priority, store.now(), store.now()))
        conn.commit()
    tool_context.state["ticket_id"] = ticket_id
    tool_context.state["ticket_user"] = username
    return {"status": "ok", "ticket_id": ticket_id}


def get_asset(username: str) -> dict:
    """List the assets assigned to a user."""
    with store.connect() as conn:
        rows = conn.execute("SELECT asset_id, kind, model, status FROM assets WHERE owner = ?",
                            (username,)).fetchall()
    return {"status": "ok", "assets": [store.as_json(r) for r in rows]}


def get_ticket_history(username: str) -> dict:
    """List earlier tickets of a user."""
    with store.connect() as conn:
        rows = conn.execute("SELECT ticket_id, summary, status, resolution FROM tickets WHERE username = ? "
                            "ORDER BY created_at", (username,)).fetchall()
    return {"status": "ok", "tickets": [store.as_json(r) for r in rows]}


def run_diagnostic(asset_id: str, check: str, tool_context: ToolContext) -> dict:
    """Run a named diagnostic check against an asset (executes the diagnostic probe)."""
    if check not in {"ping", "disk", "network"}:
        return {"status": "error", "error": f"unknown check {check}"}
    probe = subprocess.run([sys.executable, "-c", f"print('{check} ok for {asset_id}')"],
                           capture_output=True, text=True, timeout=30, check=False)
    resolved = probe.returncode == 0
    tool_context.state["diagnosis_status"] = "resolved" if resolved else "unresolved"
    return {"status": "ok", "asset_id": asset_id, "check": check, "output": probe.stdout.strip(),
            "resolved": resolved}


def update_ticket(ticket_id: str, status: str, resolution: str) -> dict:
    """Update an incident ticket's status and resolution."""
    with store.connect() as conn:
        cur = conn.execute("UPDATE tickets SET status = ?, resolution = ?, updated_at = ? WHERE ticket_id = ?",
                           (status, resolution, store.now(), ticket_id))
        conn.commit()
    return {"status": "ok" if cur.rowcount else "not_found", "ticket_id": ticket_id}


def notify_user(username: str, subject: str, body: str) -> dict:
    """Send an e-mail notification to a user (queued in the outbox)."""
    with store.connect() as conn:
        row = conn.execute("SELECT email FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return {"status": "not_found", "username": username}
        message_id = store.new_id("MSG")
        conn.execute("INSERT INTO outbox VALUES (?, ?, ?, ?, ?)", (message_id, row["email"], subject, body,
                                                                  store.now()))
        conn.commit()
    return {"status": "queued", "message_id": message_id}
