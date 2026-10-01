"""Collect real tool definitions from published MCP servers (the benign side).

Starts each server over stdio, calls ``tools/list`` and writes every definition
to a JSON file. Servers that need credentials are started with dummy values:
listing tools never uses them. Servers that fail to start are reported and skipped.

    python benchmarks/collect_tools.py real_tools.json
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

DUMMY = {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "x",
    "BRAVE_API_KEY": "x",
    "SLACK_BOT_TOKEN": "xoxb-x",
    "SLACK_TEAM_ID": "T0",
    "API_KEY": "x",
    "NOTION_TOKEN": "x",
    "FIRECRAWL_API_KEY": "x",
    "GOOGLE_MAPS_API_KEY": "x",
    "EXA_API_KEY": "x",
    "TAVILY_API_KEY": "x",
    "POSTGRES_URL": "postgresql://x@localhost/x",
}

SERVERS: dict[str, list[str]] = {
    "everything": ["npx", "-y", "@modelcontextprotocol/server-everything"],
    "memory": ["npx", "-y", "@modelcontextprotocol/server-memory"],
    "sequential-thinking": [
        "npx",
        "-y",
        "@modelcontextprotocol/server-sequential-thinking",
    ],
    "filesystem": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."],
    "github": ["npx", "-y", "@modelcontextprotocol/server-github"],
    "puppeteer": ["npx", "-y", "@modelcontextprotocol/server-puppeteer"],
    "brave-search": ["npx", "-y", "@modelcontextprotocol/server-brave-search"],
    "slack": ["npx", "-y", "@modelcontextprotocol/server-slack"],
    "playwright": ["npx", "-y", "@playwright/mcp@latest"],
    "context7": ["npx", "-y", "@upstash/context7-mcp"],
    "notion": ["npx", "-y", "@notionhq/notion-mcp-server"],
    "firecrawl": ["npx", "-y", "firecrawl-mcp"],
    "exa": ["npx", "-y", "exa-mcp-server"],
    "tavily": ["npx", "-y", "tavily-mcp"],
    "chrome-devtools": ["npx", "-y", "chrome-devtools-mcp@latest"],
    "fetch": ["uvx", "mcp-server-fetch"],
    "git": ["uvx", "mcp-server-git"],
    "time": ["uvx", "mcp-server-time"],
    "sqlite": ["uvx", "mcp-server-sqlite", "--db-path", "x.db"],
}


async def collect(name: str, command: list[str]) -> list[dict[str, Any]]:
    params = StdioServerParameters(command=command[0], args=command[1:], env=DUMMY)
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await asyncio.wait_for(session.initialize(), 120)
        tools = (await asyncio.wait_for(session.list_tools(), 60)).tools
        return [
            {
                "server": name,
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.input_schema,
            }
            for t in tools
        ]


async def main(out: Path) -> None:
    collected: list[dict[str, Any]] = []
    for name, command in SERVERS.items():
        try:
            tools = await collect(name, command)
        except Exception as exc:
            print(f"skip {name}: {type(exc).__name__}: {str(exc)[:80]}")
            continue
        collected.extend(tools)
        print(f"ok   {name}: {len(tools)} tools")
    out.write_text(json.dumps(collected, indent=1) + "\n", encoding="utf-8")
    print(f"{len(collected)} tool definitions -> {out}")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1] if len(sys.argv) > 1 else "real_tools.json")))
