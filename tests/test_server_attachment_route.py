"""End-to-end tests for the /attachments/{path} HTTP upload/download route.

Verifies the raw-bytes path documented in server.py works against the real
ASGI app: PUT/GET with an Authorization header write/read the file directly,
bypassing the MCP tool-call/base64 channel entirely.
"""
from __future__ import annotations

import time

import httpx
import pytest
from fastmcp.server.auth import AccessToken, TokenVerifier

from obsidian_mcp import server


def _client():
    transport = httpx.ASGITransport(app=server.mcp.http_app())
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


# ── PUT (upload) ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upload_route_writes_file(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")

    async with _client() as client:
        resp = await client.put(
            "/attachments/docs/file.pdf",
            content=b"PDF-CONTENT-\x00\x01\x02",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 200
    assert resp.json()["status"] == "written"
    assert (tmp_path / "docs" / "file.pdf").read_bytes() == b"PDF-CONTENT-\x00\x01\x02"


@pytest.mark.asyncio
async def test_upload_route_rejects_wrong_key(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "correct-key")

    async with _client() as client:
        resp = await client.put(
            "/attachments/file.png",
            content=b"data",
            headers={"Authorization": "Bearer wrong-key"},
        )

    assert resp.status_code == 401
    assert not (tmp_path / "file.png").exists()


@pytest.mark.asyncio
async def test_upload_route_rejects_markdown(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")

    async with _client() as client:
        resp = await client.put(
            "/attachments/note.md",
            content=b"# not allowed here",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [".env", ".hidden/file.png", "extensionless", "script.py", "script.sh", "config.yaml"],
)
async def test_upload_route_rejects_unsafe_attachment_names(path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")

    async with _client() as client:
        resp = await client.put(
            f"/attachments/{path}",
            content=b"unsafe",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_upload_route_rejects_declared_oversize(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setenv("MAX_ATTACHMENT_BYTES", "3")

    async with _client() as client:
        resp = await client.put(
            "/attachments/file.png",
            content=b"1234",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 413
    assert not (tmp_path / "file.png").exists()


@pytest.mark.asyncio
async def test_upload_route_rejects_streamed_oversize(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setenv("MAX_ATTACHMENT_BYTES", "3")

    async def body():
        yield b"12"
        yield b"34"

    async with _client() as client:
        resp = await client.put(
            "/attachments/file.png",
            content=body(),
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 413
    assert not (tmp_path / "file.png").exists()


# ── GET (download) ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_download_route_reads_file(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "file.pdf").write_bytes(b"PDF-CONTENT-\x00\x01\x02")
    monkeypatch.setenv("API_KEY", "test-key")

    async with _client() as client:
        resp = await client.get(
            "/attachments/docs/file.pdf",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 200
    assert resp.content == b"PDF-CONTENT-\x00\x01\x02"
    assert resp.headers["content-type"] == "application/pdf"


@pytest.mark.asyncio
async def test_download_route_missing_file(vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")

    async with _client() as client:
        resp = await client.get(
            "/attachments/ghost.png",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_download_route_rejects_wrong_key(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    (tmp_path / "file.png").write_bytes(b"data")
    monkeypatch.setenv("API_KEY", "correct-key")

    async with _client() as client:
        resp = await client.get(
            "/attachments/file.png",
            headers={"Authorization": "Bearer wrong-key"},
        )

    assert resp.status_code == 401


# ── OAuth-style tokens (mcp.auth), independent of the static API_KEY ─────────

class _FakeOAuthVerifier(TokenVerifier):
    """Stands in for GitHubProvider/MultiAuth without hitting the network."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if token == "valid-oauth-token":
            return AccessToken(token=token, client_id="oauth-user", scopes=[])
        return None


@pytest.mark.asyncio
async def test_upload_route_accepts_oauth_token(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.setattr(server.mcp, "auth", _FakeOAuthVerifier())

    async with _client() as client:
        resp = await client.put(
            "/attachments/docs/file.pdf",
            content=b"PDF-CONTENT",
            headers={"Authorization": "Bearer valid-oauth-token"},
        )

    assert resp.status_code == 200
    assert (tmp_path / "docs" / "file.pdf").read_bytes() == b"PDF-CONTENT"


@pytest.mark.asyncio
async def test_upload_route_rejects_invalid_oauth_token(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.setattr(server.mcp, "auth", _FakeOAuthVerifier())

    async with _client() as client:
        resp = await client.put(
            "/attachments/docs/file.pdf",
            content=b"PDF-CONTENT",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

    assert resp.status_code == 401
    assert not (tmp_path / "docs" / "file.pdf").exists()


@pytest.mark.asyncio
async def test_upload_route_accepts_api_key_alongside_oauth(tmp_path, vault_factory, monkeypatch):
    """Both auth variants must work at the same time, not either/or."""
    vault_factory({})
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setattr(server.mcp, "auth", _FakeOAuthVerifier())

    async with _client() as client:
        resp = await client.put(
            "/attachments/docs/file.pdf",
            content=b"PDF-CONTENT",
            headers={"Authorization": "Bearer test-key"},
        )

    assert resp.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "PUT"])
async def test_old_signed_urls_require_bearer_auth(method, tmp_path, vault_factory, monkeypatch):
    import hashlib
    import hmac
    import json

    vault_factory({})
    monkeypatch.setenv("API_KEY", "master-key")
    path = tmp_path / "file.png"
    path.write_bytes(b"original")
    expiry = int(time.time()) + 60
    message = json.dumps([method, "file.png", "default", expiry], separators=(",", ":"))
    signature = hmac.new(b"master-key", message.encode(), hashlib.sha256).hexdigest()
    async with _client() as client:
        response = await client.request(
            method, f"/attachments/file.png?exp={expiry}&sig={signature}", content=b"changed"
        )
    assert response.status_code == 401
    assert path.read_bytes() == b"original"


# ── multi-vault mode ─────────────────────────────────────────────────────

def _write_vaults_config(tmp_path):
    vault_a, vault_b = tmp_path / "a", tmp_path / "b"
    vault_a.mkdir()
    vault_b.mkdir()
    import json
    data = {
        "vaults": {"private": {"path": str(vault_a)}, "monari": {"path": str(vault_b)}},
        "identities": [
            {"type": "api_key", "value": "sk-private-only", "vaults": ["private"]},
            {"type": "api_key", "value": "sk-both", "vaults": ["private", "monari"], "default": "private"},
            {"type": "github_login", "value": "octocat", "vaults": ["monari"]},
        ],
    }
    config_path = tmp_path / "vaults.json"
    config_path.write_text(json.dumps(data), encoding="utf-8")
    return config_path, vault_a, vault_b


def _enable_multi_vault_http(monkeypatch, config_path):
    monkeypatch.setenv("VAULTS_CONFIG", str(config_path))
    monkeypatch.setenv("TRANSPORT", "http")


@pytest.mark.asyncio
async def test_bearer_token_route_scoped_to_identitys_default_vault(tmp_path, monkeypatch):
    config_path, vault_a, vault_b = _write_vaults_config(tmp_path)
    _enable_multi_vault_http(monkeypatch, config_path)
    import obsidian_mcp.config as cfg_mod
    cfg_mod._config = None
    # mcp.auth was built once at module-import time, before VAULTS_CONFIG
    # existed — rebuild it against the now-current env, same as production
    # startup does (VAULTS_CONFIG is already set before the process's very
    # first import there). Same reasoning as the _FakeOAuthVerifier tests
    # above, just with the real multi-key provider instead of a stand-in.
    monkeypatch.setattr(server.mcp, "auth", server._build_auth())

    async with _client() as client:
        resp = await client.put(
            "/attachments/file.png",
            content=b"data",
            headers={"Authorization": "Bearer sk-private-only"},
        )

    assert resp.status_code == 200
    assert (vault_a / "file.png").read_bytes() == b"data"
    assert not (vault_b / "file.png").exists()


@pytest.mark.asyncio
async def test_bearer_token_route_honors_vault_query_param(tmp_path, monkeypatch):
    config_path, vault_a, vault_b = _write_vaults_config(tmp_path)
    _enable_multi_vault_http(monkeypatch, config_path)
    import obsidian_mcp.config as cfg_mod
    cfg_mod._config = None
    monkeypatch.setattr(server.mcp, "auth", server._build_auth())

    async with _client() as client:
        resp = await client.put(
            "/attachments/file.png?vault=monari",
            content=b"data",
            headers={"Authorization": "Bearer sk-both"},
        )

    assert resp.status_code == 200
    assert (vault_b / "file.png").read_bytes() == b"data"
    assert not (vault_a / "file.png").exists()


@pytest.mark.asyncio
async def test_bearer_token_route_rejects_vault_outside_identity(tmp_path, monkeypatch):
    config_path, vault_a, vault_b = _write_vaults_config(tmp_path)
    _enable_multi_vault_http(monkeypatch, config_path)
    import obsidian_mcp.config as cfg_mod
    cfg_mod._config = None
    monkeypatch.setattr(server.mcp, "auth", server._build_auth())

    async with _client() as client:
        resp = await client.put(
            "/attachments/file.png?vault=monari",
            content=b"data",
            headers={"Authorization": "Bearer sk-private-only"},
        )

    assert resp.status_code == 403
    assert not (vault_a / "file.png").exists()
    assert not (vault_b / "file.png").exists()


@pytest.mark.asyncio
async def test_bearer_token_route_enforces_selected_vault_write_policy(tmp_path, monkeypatch):
    vault_a, vault_b = tmp_path / "a", tmp_path / "b"
    vault_a.mkdir()
    vault_b.mkdir()
    import json

    config_path = tmp_path / "vaults.json"
    config_path.write_text(
        json.dumps(
            {
                "vaults": {
                    "private": {"path": str(vault_a)},
                    "monari": {"path": str(vault_b), "write_paths": ["allowed/"]},
                },
                "identities": [
                    {
                        "type": "api_key",
                        "value": "sk-both",
                        "vaults": ["private", "monari"],
                        "default": "private",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("VAULTS_CONFIG", str(config_path))
    monkeypatch.setenv("TRANSPORT", "sse")
    import obsidian_mcp.config as cfg_mod

    cfg_mod._config = None
    monkeypatch.setattr(server.mcp, "auth", server._build_auth())

    async with _client() as client:
        denied = await client.put(
            "/attachments/file.png?vault=monari",
            content=b"denied",
            headers={"Authorization": "Bearer sk-both"},
        )
        allowed = await client.put(
            "/attachments/allowed/file.png?vault=monari",
            content=b"allowed",
            headers={"Authorization": "Bearer sk-both"},
        )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert not (vault_b / "file.png").exists()
    assert (vault_b / "allowed" / "file.png").read_bytes() == b"allowed"


@pytest.mark.asyncio
async def test_downloads_are_not_cacheable_across_identity_changes(tmp_path, monkeypatch):
    import json

    import obsidian_mcp.config as cfg_mod

    config_path, vault_a, vault_b = _write_vaults_config(tmp_path)
    config = json.loads(config_path.read_text())
    config["identities"][1]["default"] = "monari"
    config_path.write_text(json.dumps(config))
    (vault_a / "file.png").write_bytes(b"private")
    (vault_b / "file.png").write_bytes(b"monari")
    _enable_multi_vault_http(monkeypatch, config_path)
    cfg_mod._config = None
    monkeypatch.setattr(server.mcp, "auth", server._build_auth())

    # Reuse one client and URL while changing the authenticated identity.
    # This verifies the server's cache directive, not browser cache internals.
    async with _client() as client:
        for key, expected in [("sk-private-only", b"private"), ("sk-both", b"monari")]:
            response = await client.get(
                "/attachments/file.png", headers={"Authorization": f"Bearer {key}"}
            )
            assert response.status_code == 200
            assert response.content == expected
            assert response.headers["cache-control"] == "no-store"
