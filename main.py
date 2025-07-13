from fastmcp import FastMCP
from dotenv import load_dotenv
import asyncio
from starlette.requests import Request
from starlette.responses import JSONResponse
from virus_total.vt import vt_mcp
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from fastmcp.server.auth import BearerAuthProvider
import inspect

public_key_pem = inspect.cleandoc(
    """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsQ1iRuOUzcsHkXScTFn6
    3nSvejIalBtuuVxdFHCq3XxqNiqdh4i7mSjIIMt2PXMktaUD6j9p/rQ8rQEEqm5S
    qW9oAb63yMy8FhW/jB54XrR4e66s7f7lS+LuopJA3UOBh1dXHzhLYuQDx6CdwwjK
    oweE7B1I1uS/QA6tkqHxqpZwcIquXjU6QhXU5fdGsnTkOKUK68IPB+SwSKkhrxYH
    ue32K3AzJaOQ7hRlSRlcfkcAwGRF2cFx8X1uknDWZXr4nzz3nQePvB+4g6RN1hxC
    ah4ousDFin05QZKtsOKUedURg6XeIslnoEbqHHMQl/Tv0w4AragKQxX0ewAqFY6x
    4wIDAQAB
    -----END PUBLIC KEY-----
    """
)
auth = BearerAuthProvider(
    public_key=public_key_pem,
    issuer="development-test",
    audience="ti-mcp-server",
)

main_mcp = FastMCP(
    name="Threat Intelligence MCP server",
    instructions="""
    A server providing threat intelligence tools to help AI assistants for further investigation.
    """,
    auth=auth,
)

@main_mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    return JSONResponse({"status": "healthy"})


async def setup():
    load_dotenv()
    await main_mcp.import_server(vt_mcp, prefix="virus_total")
    main_mcp.add_middleware(
        RateLimitingMiddleware(max_requests_per_second=10, burst_capacity=20)
    )
    await main_mcp.run_async(
        transport="sse",
        host="0.0.0.0",
        port=8081,
    )


if __name__ == "__main__":
    asyncio.run(setup())
    main_mcp.http_app()
