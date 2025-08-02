from fastmcp import FastMCP
from dotenv import load_dotenv
import asyncio
import os
from starlette.requests import Request
from starlette.responses import JSONResponse
from virus_total.vt import vt_mcp
from abuseipdb.abuseipdb import abuseipdb_mcp

main_mcp = FastMCP(
    name="Threat Intelligence MCP server",
    instructions="""
    A server providing threat intelligence tools to help AI assistants for further investigation.
    """,
)

LOG_LEVEL = os.getenv("TI_MCP_LOG_LEVEL", "info").lower()

@main_mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    return JSONResponse({"status": "healthy"})

async def setup():
    load_dotenv()
    await main_mcp.import_server(vt_mcp, prefix="virus_total")
    await main_mcp.import_server(abuseipdb_mcp, prefix="abuseipdb")
    await main_mcp.run_async(
        transport="http",
        host="0.0.0.0",
        port=8081,
        log_level=LOG_LEVEL,
    )

if __name__ == "__main__":
    asyncio.run(setup())
    main_mcp.http_app()