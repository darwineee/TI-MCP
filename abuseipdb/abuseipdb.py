from os import getenv
from fastmcp import FastMCP
import requests

base_url = "https://api.abuseipdb.com/api/v2/check/"

api_key = getenv("ABUSEIPDB_API_KEY")
if not api_key:
    raise ValueError("AbuseIPDB API key not found in environment variables")

auth_header = {
    "Key": api_key,
    "Accept": "application/json"
}

abuseipdb_mcp = FastMCP(
    name="AbuseIPDB MCP server",
    instructions="""
    Using the `check_endpoint` tool with an IP address to check it against AbuseIPDB.
    """,
)

@abuseipdb_mcp.tool
def check_endpoint(ip: str, maxAgeInDays: int = 90) -> dict:
    """
    Checks the AbuseIPDB API for information about a specific IP address. 

    Args:
        ip (str): The IP address to search.
        maxAgeInDays (int): The maximum age of the data to retrieve in days. Default is 90.
    Returns:
        dict: The response from the AbuseIPDB API containing information about the IP address like: Geolocation, domain name, report history,...
        or an error message if the request fails.
    """
    params = {
        "ipAddress": ip,
        "maxAgeInDays": maxAgeInDays
    }
    response = requests.get(base_url, headers=auth_header, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to retrieve data for IP '{ip}'. Status code: {response.status_code}"
        }