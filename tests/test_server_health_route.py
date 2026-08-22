"""Tests for the unauthenticated /health liveness/readiness route."""
from __future__ import annotations

import httpx
import pytest

from obsidian_mcp import server


def _client():
    transport = httpx.ASGITransport(app=server.mcp.http_app())
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
async def test_health_before_startup_returns_503(monkeypatch):
    monkeypatch.setattr(server, "_cfg", None)
    monkeypatch.setattr(server, "_index", None)

    async with _client() as client:
        resp = await client.get("/health")

    assert resp.status_code == 503
    assert resp.json() == {"status": "starting"}


@pytest.mark.asyncio
async def test_health_ready_returns_ok(tmp_path, vault_factory, monkeypatch):
    idx = vault_factory({"note.md": "# Hello"})
    monkeypatch.setattr(server, "_cfg", server.get_config())
    monkeypatch.setattr(server, "_index", idx)

    async with _client() as client:
        resp = await client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "vault_path" not in body
    assert body["index_ready"] is True


@pytest.mark.asyncio
async def test_health_echoes_explicit_local_smoke_startup_nonce(vault_factory, monkeypatch):
    idx = vault_factory({})
    monkeypatch.setenv("LOCAL_SMOKE_TEST_NONCE", "unique-launch")
    monkeypatch.setattr(server, "_cfg", server.get_config())
    monkeypatch.setattr(server, "_index", idx)

    async with _client() as client:
        resp = await client.get("/health")

    assert resp.status_code == 200
    assert resp.json()["startup_nonce"] == "unique-launch"


@pytest.mark.asyncio
async def test_health_requires_no_auth(tmp_path, vault_factory, monkeypatch):
    """/health must stay reachable even when API_KEY/OAuth are configured —
    it exposes no vault content, only process liveness."""
    idx = vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setattr(server, "_cfg", server.get_config())
    monkeypatch.setattr(server, "_index", idx)

    async with _client() as client:
        resp = await client.get("/health")

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_detects_runtime_recovery_required_journal(tmp_path, vault_factory, monkeypatch):
    idx = vault_factory({})
    cfg = server.get_config()
    journal_dir = cfg.transaction_path / "runtime-fault"
    journal_dir.mkdir(parents=True)
    (journal_dir / "journal.json").write_text('{"operation_id":"runtime-fault","status":"recovery_required"}')
    monkeypatch.setattr(server, "_cfg", cfg)
    monkeypatch.setattr(server, "_index", idx)

    async with _client() as client:
        resp = await client.get("/health")

    assert resp.status_code == 503
    assert resp.json()["status"] == "degraded"
    assert resp.json()["incomplete_transactions"] == 1
