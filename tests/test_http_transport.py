"""Tests for modern Streamable HTTP protocol support."""

import json

import httpx
import pytest

from mcpguard.http_transport import MODERN_PROTOCOL_VERSION, ModernHttpClient


def _response(payload: dict[str, object], content_type: str = "application/json"):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["MCP-Protocol-Version"] == MODERN_PROTOCOL_VERSION
        body = json.loads(request.content)
        assert request.headers["Mcp-Method"] == body["method"]
        assert body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == (
            MODERN_PROTOCOL_VERSION
        )
        return httpx.Response(
            200,
            json=payload if content_type == "application/json" else None,
            text=(
                f"event: message\ndata: {json.dumps(payload)}\n\n"
                if content_type == "text/event-stream"
                else None
            ),
            headers={"content-type": content_type},
        )

    return handler


async def test_modern_discover_reads_capabilities_and_server_info() -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "capabilities": {"tools": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "modern-server",
                    "version": "2.0",
                }
            },
        },
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(_response(payload))
    ) as raw:
        client = ModernHttpClient("https://example.test/mcp", client=raw)
        result = await client.discover()

    assert result["capabilities"] == {"tools": {}}
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == (
        "modern-server"
    )


async def test_modern_client_parses_sse_response() -> None:
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(_response(payload, "text/event-stream"))
    ) as raw:
        result = await ModernHttpClient("https://example.test/mcp", client=raw).request(
            "tools/list"
        )
    assert result == {"tools": []}


async def test_modern_client_raises_protocol_error() -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32601, "message": "not found"},
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(_response(payload))
    ) as raw:
        with pytest.raises(RuntimeError, match="-32601.*not found"):
            await ModernHttpClient("https://example.test/mcp", client=raw).discover()


async def test_tool_call_sets_name_header() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Mcp-Name"] == "echo"
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as raw:
        await ModernHttpClient("https://example.test/mcp", client=raw).call_tool(
            "echo", {"value": "hello"}
        )
