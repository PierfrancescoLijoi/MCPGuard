import httpx
import pytest

from mcpguard.http_transport import ModernHttpClient


async def test_custom_auth_headers_are_sent() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.headers["X-Tenant"] == "acme"
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as raw:
        await ModernHttpClient(
            "https://example.test/mcp",
            client=raw,
            headers={"Authorization": "Bearer test-token", "X-Tenant": "acme"},
        ).discover()


def test_reserved_headers_cannot_be_overridden() -> None:
    with pytest.raises(ValueError, match="reserved"):
        ModernHttpClient(
            "https://example.test/mcp", headers={"Mcp-Method": "tools/call"}
        )
