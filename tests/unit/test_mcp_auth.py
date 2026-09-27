"""Security tests for the public FastMCP authentication boundary."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

import fastmcp_server


def test_auth_provider_requires_complete_configuration():
    with pytest.raises(RuntimeError, match="required"):
        fastmcp_server._build_auth_provider({"FF_AUTH_JWKS_URI": "https://id.example/jwks"})


def test_auth_provider_rejects_multiple_key_sources():
    with pytest.raises(RuntimeError, match="exactly one"):
        fastmcp_server._build_auth_provider(
            {
                "FF_AUTH_PUBLIC_KEY": "public-key",
                "FF_AUTH_JWKS_URI": "https://id.example/jwks",
                "FF_AUTH_ISSUER": "https://id.example/",
                "FF_AUTH_AUDIENCE": "fantasy-mcp",
                "FF_AUTH_BASE_URL": "https://fantasy.example/",
            }
        )


def test_scope_check_rejects_unlisted_caller(monkeypatch):
    monkeypatch.setenv("FF_AUTH_ALLOWED_CLIENT_IDS", "approved-client")
    token = SimpleNamespace(client_id="other-client", scopes=[fastmcp_server.READ_SCOPE])
    with patch.object(fastmcp_server, "AUTH_PROVIDER", object()), patch.object(
        fastmcp_server, "get_access_token", return_value=token
    ):
        with pytest.raises(PermissionError, match="not authorized"):
            fastmcp_server._require_scope(fastmcp_server.READ_SCOPE)


def test_scope_check_rejects_missing_admin_scope(monkeypatch):
    monkeypatch.setenv("FF_AUTH_ALLOWED_CLIENT_IDS", "approved-client")
    token = SimpleNamespace(client_id="approved-client", scopes=[fastmcp_server.READ_SCOPE])
    with patch.object(fastmcp_server, "AUTH_PROVIDER", object()), patch.object(
        fastmcp_server, "get_access_token", return_value=token
    ):
        with pytest.raises(PermissionError, match="fantasy:admin"):
            fastmcp_server._require_scope(fastmcp_server.ADMIN_SCOPE)


def test_scope_check_accepts_allowlisted_scoped_caller(monkeypatch):
    monkeypatch.setenv("FF_AUTH_ALLOWED_CLIENT_IDS", "approved-client")
    token = SimpleNamespace(
        client_id="approved-client",
        scopes=[fastmcp_server.READ_SCOPE, fastmcp_server.ADMIN_SCOPE],
    )
    with patch.object(fastmcp_server, "AUTH_PROVIDER", object()), patch.object(
        fastmcp_server, "get_access_token", return_value=token
    ):
        fastmcp_server._require_scope(fastmcp_server.ADMIN_SCOPE)


def test_public_listener_requires_auth(monkeypatch):
    monkeypatch.setenv("FF_ALLOW_PUBLIC_HTTP", "1")
    monkeypatch.setenv("FF_AUTH_ALLOWED_CLIENT_IDS", "approved-client")
    monkeypatch.setattr(fastmcp_server, "AUTH_PROVIDER", None)
    with pytest.raises(RuntimeError, match="without JWT authentication"):
        fastmcp_server.run_http_server(host="0.0.0.0", show_banner=False)
