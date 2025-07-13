from os import getenv
from fastmcp import FastMCP
import requests
from tenacity import retry, stop_after_attempt, wait_fixed

api_key = getenv("VT_API_KEY")
if not api_key:
    raise ValueError("VirusTotal API key not found in environment variables")

base_url = "https://www.virustotal.com/api/v3/"
auth_header = {"x-apikey": api_key}

vt_mcp = FastMCP(
    name="Virus Total MCP server",
    instructions="""
    Call the `/check_hash` endpoint with a file hash to check it against VirusTotal.
    """,
)

@retry(stop=stop_after_attempt(3), wait=wait_fixed(15))
@vt_mcp.tool
def check_hash(hash: str) -> dict:
    """
    Check a file hash against VirusTotal.

    Args:
        hash (str): The hash to check.
    Returns:
        dict: The response from VirusTotal, or an error message if the request fails.
    """

    response = requests.get(f"{base_url}files/{hash}", headers=auth_header)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to retrieve data for hash {hash}. Status code: {response.status_code}"
        }
