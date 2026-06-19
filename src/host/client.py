"""MCPHost — connects to MCP servers via stdio transport and exposes their tools."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from providers.base import ToolSpec

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    _HAS_MCP = True
except ImportError:
    _HAS_MCP = False

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Display metadata for a discovered tool."""
    name: str
    description: str
    server_name: str
    input_schema: Dict[str, Any]


class MCPHost:
    """Manages connections to one or more MCP servers and provides a unified tool interface.

    Usage::

        async with MCPHost(server_specs) as host:
            print(host.tools)
            result = await host.call_tool("calculator__add", {"a": 1, "b": 2})
    """

    def __init__(self, server_specs: List[Any]) -> None:
        """
        Args:
            server_specs: List of ServerSpec (from config) or compatible objects with
                          name, command, args, env attributes.
        """
        if not _HAS_MCP:
            raise ImportError("The 'mcp' package is required. Install it with: pip install mcp")
        self._specs = server_specs
        self._sessions: Dict[str, ClientSession] = {}
        self._tool_map: Dict[str, str] = {}  # tool_name -> server_name
        self._tool_specs: List[ToolSpec] = []
        self._tool_infos: List[ToolInfo] = []
        self._contexts: List[Any] = []  # keep context managers alive

    async def __aenter__(self) -> "MCPHost":
        for spec in self._specs:
            try:
                await self._connect(spec)
            except Exception:
                logger.exception("Failed to connect to server %s", spec.name)
        await self._discover()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for ctx in self._contexts:
            try:
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass
        self._sessions.clear()
        self._contexts.clear()

    async def _connect(self, spec: Any) -> None:
        params = StdioServerParameters(
            command=spec.command,
            args=list(spec.args) if spec.args else [],
            env=dict(spec.env) if spec.env else None,
        )
        ctx = stdio_client(params)
        read_stream, write_stream = await ctx.__aenter__()
        self._contexts.append(ctx)
        session = ClientSession(read_stream, write_stream)
        await session.__aenter__()
        self._contexts.append(session)
        await session.initialize()
        self._sessions[spec.name] = session
        logger.info("Connected to MCP server: %s", spec.name)

    async def _discover(self) -> None:
        """List tools from all connected servers and build unified index."""
        self._tool_specs.clear()
        self._tool_infos.clear()
        self._tool_map.clear()

        for server_name, session in self._sessions.items():
            try:
                result = await session.list_tools()
                for tool in result.tools:
                    qualified = f"{server_name}__{tool.name}"
                    schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}
                    self._tool_map[qualified] = server_name
                    self._tool_specs.append(ToolSpec(
                        name=qualified,
                        description=tool.description or "",
                        input_schema=schema,
                    ))
                    self._tool_infos.append(ToolInfo(
                        name=qualified,
                        description=tool.description or "",
                        server_name=server_name,
                        input_schema=schema,
                    ))
            except Exception:
                logger.exception("Failed to list tools from %s", server_name)

    @property
    def tools(self) -> List[ToolSpec]:
        """All discovered tools across servers."""
        return list(self._tool_specs)

    @property
    def tool_infos(self) -> List[ToolInfo]:
        """Rich tool info for display."""
        return list(self._tool_infos)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        """Invoke a tool by its qualified name and return the text result."""
        server_name = self._tool_map.get(name)
        if not server_name:
            raise ValueError(f"Unknown tool: {name!r}")
        session = self._sessions[server_name]
        # Strip server prefix to get the bare tool name
        bare_name = name.split("__", 1)[1] if "__" in name else name
        result = await session.call_tool(bare_name, arguments)
        # Extract text from result content
        parts: List[str] = []
        for item in result.content:
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return "\n".join(parts) if parts else ""
