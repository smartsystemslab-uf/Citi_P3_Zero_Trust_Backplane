from fastapi.testclient import TestClient

from zt_backplane.pdp_service import create_app


def test_authorize_endpoint(engine):
    client = TestClient(create_app(engine))
    response = client.post(
        "/v1/authorize",
        json={
            "subject": "fraud_agent",
            "resource": "transaction_history",
            "action": "read",
            "context": {"workflow": "fraud_review", "risk": "medium"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW_WITH_OBLIGATIONS"
    assert body["cache_control"] == "NO_STORE"
    assert body["policy_version"]


def test_health_endpoint(engine):
    client = TestClient(create_app(engine))
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["policy_count"] >= 1


def test_reload_is_disabled_without_admin_token(engine, monkeypatch):
    monkeypatch.delenv("ZT_ADMIN_TOKEN", raising=False)
    client = TestClient(create_app(engine))
    response = client.post("/v1/admin/reload")
    assert response.status_code == 503
