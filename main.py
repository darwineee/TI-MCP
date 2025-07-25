from fastmcp import FastMCP
from dotenv import load_dotenv
import asyncio
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from virus_total.vt import vt_mcp
from shodan.shodan import shodan_mcp

main_mcp = FastMCP(
    name="Threat Intelligence MCP server",
    instructions="""
    A server providing threat intelligence tools to help AI assistants for further investigation.
    """,
)

@main_mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    return JSONResponse({"status": "healthy"})

async def setup():
    load_dotenv()
    await main_mcp.import_server(vt_mcp, prefix="virus_total")
    await main_mcp.import_server(shodan_mcp, prefix="shodan")
    main_mcp.add_middleware(RateLimitingMiddleware(
        max_requests_per_second=10,
        burst_capacity=20
    ))
    await main_mcp.run_async(
        transport="sse",
        host="0.0.0.0",
        port=8081,
    )

if __name__ == "__main__":
    asyncio.run(setup())
    main_mcp.http_app()