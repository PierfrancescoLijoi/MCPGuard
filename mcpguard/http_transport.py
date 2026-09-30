"""Streamable HTTP support for the MCP 2026-07-28 stateless lifecycle."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx

from mcpguard import __version__

MODERN_PROTOCOL_VERSION = "2026-07-28"
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
_RESERVED_HEADERS = {
    "mcp-protocol-version",
    "mcp-method",
    "mcp-name",
    "content-type",
    "accept",
}


class McpProtocolError(RuntimeError):
    """A well-formed JSON-RPC error returned by the MCP server."""


class ModernHttpClient:
    """Small, dependency-light client for stateless MCP Streamable HTTP."""

    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError("Streamable HTTP target must use http:// or https://")
        self.url = url
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient()
        self._timeout = timeout
        self._request_id = 0
        self._headers = dict(headers or {})
        overridden = _RESERVED_HEADERS.intersection(
            key.lower() for key in self._headers
        )
        if overridden:
            raise ValueError("reserved MCP transport headers cannot be overridden")

    async def discover(self) -> dict[str, Any]:
        """Discover capabilities without creating a protocol session."""
        return await self.request("server/discover")

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self.request("tools/list")
        tools = result.get("tools", [])
        return list(tools) if isinstance(tools, list) else []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a named tool using a fully self-describing modern request."""
        return await self.request(
            "tools/call", {"name": name, "arguments": arguments}, name=name
        )

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Send one stateless JSON-RPC request and return its result."""
        self._request_id += 1
        request_params = dict(params or {})
        request_params["_meta"] = {
            PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
            CLIENT_CAPABILITIES_META_KEY: {},
            CLIENT_INFO_META_KEY: {"name": "mcpguard", "version": __version__},
        }
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": request_params,
        }
        headers = {
            **self._headers,
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": method,
        }
        if name is not None:
            headers["Mcp-Name"] = name

        response = await self._client.post(
            self.url, json=payload, headers=headers, timeout=self._timeout
        )
        response.raise_for_status()
        envelope = self._parse_response(response)
        error = envelope.get("error")
        if isinstance(error, dict):
            raise McpProtocolError(
                f"MCP error {error.get('code')}: "
                f"{error.get('message', 'unknown error')}"
            )
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("MCP response did not contain an object result")
        return result

    async def aclose(self) -> None:
        """Close the internally owned HTTP connection pool."""
        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _parse_response(response: httpx.Response) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    payload = json.loads(line[5:].strip())
                    if isinstance(payload, dict):
                        return payload
            raise RuntimeError("SSE response did not contain a JSON-RPC message")
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("MCP response must be a JSON object")
        return payload
