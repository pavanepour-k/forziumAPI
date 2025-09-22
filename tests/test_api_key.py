"""Tests for API key query dependency."""

from __future__ import annotations

import pytest

from forzium import Depends, ForziumApp
from forzium.dependency import Request
from forzium.responses import HTTPException
from forzium.security import api_key_query
from forzium.testclient import TestClient


@pytest.fixture()
def secured_app() -> ForziumApp:
    app = ForziumApp()
    app.add_security_scheme(
        "ApiKey", {"type": "apiKey", "in": "query", "name": "api_key"}
    )

    @app.get("/secure-data")
    def secure_data(api_key: str = Depends(api_key_query)) -> dict[str, str]:  # type: ignore[assignment]
        return {"message": "secured"}

    return app


def test_api_key_query_protection(secured_app: ForziumApp) -> None:
    client = TestClient(secured_app)

    ok = client.get("/secure-data", params={"api_key": "secret"})
    assert ok.status_code == 200
    assert ok.json() == {"message": "secured"}

    unauthorized = client.get("/secure-data")
    assert unauthorized.status_code == 401


def test_api_key_query_duplicate_values_return_unauthorized() -> None:
    request = Request(url="/?api_key=bad&api_key=also-bad")

    with pytest.raises(HTTPException) as excinfo:
        api_key_query(request)

    assert excinfo.value.status_code == 401


def test_api_key_query_ignores_empty_duplicates() -> None:
    request = Request(url="/?api_key=&api_key=secret")

    assert api_key_query(request) == "secret"