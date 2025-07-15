from os import getenv
from fastmcp import FastMCP
import requests

api_key = getenv("VT_API_KEY")
if not api_key:
    raise ValueError("VirusTotal API key not found in environment variables")

base_url = "https://www.virustotal.com/api/v3/"
auth_header = {"x-apikey": api_key}

vt_mcp = FastMCP(
    name="Virus Total MCP server",
    instructions="""
    Using the `check_hash` tool with a file hash to check it against VirusTotal.
    Using the `check_url` tool with a URL to analyze it against VirusTotal.
    Using the `get_url_report` tool with a URL to retrieve its report from VirusTotal.
    Using the `check_ip` tool with an IP address to check it against VirusTotal.
    Using the `check_domain` tool with a domain to check it against VirusTotal.
    """,
)

@vt_mcp.tool
def check_hash(hash: str) -> dict:
    """
    Given a {md5, sha1, sha256} hash,retrieves the pertinent analysis report including threat reputation
    and context produced from VirusTotal.

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
    

@vt_mcp.tool
def check_url(url: str) -> dict:
    """
    Analyzes your URL with 70+ antivirus products/blocklists and a myriad of other security tools
    to produce a threat score and relevant context to understand it.

    Args:
        url (str): The URL to check.
    Returns:
        dict: The response from VirusTotal, or an error message if the request fails.
    """

    response = requests.get(f"{base_url}urls/{url}", headers=auth_header)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to retrieve data for URL {url}. Status code: {response.status_code}"
        }
    

@vt_mcp.tool
def get_url_report(url: str) -> dict:
    """
    Given a URL, retrieves the pertinent analysis report including threat reputation
    and context produced from VirusTotal.

    Args:
        url (str): The URL to get the report for.
    Returns:
        dict: The report from VirusTotal, or an error message if the request fails.
    """

    response = requests.get(f"{base_url}urls/{url}/report", headers=auth_header)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to retrieve report for URL {url}. Status code: {response.status_code}"
        }

@vt_mcp.tool
def check_ip(ip: str) -> dict:
    """
    Given an IP address, retrieves the pertinent analysis report including threat reputation
    and context produced from VirusTotal.

    Args:
        ip (str): The IP address to check.
    Returns:
        dict: The response from VirusTotal, or an error message if the request fails.
    """

    response = requests.get(f"{base_url}ip_addresses/{ip}", headers=auth_header)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to retrieve data for IP {ip}. Status code: {response.status_code}"
        }

@vt_mcp.tool
def check_domain(domain: str) -> dict:
    """
    Given a domain, retrieves the pertinent analysis report including threat reputation
    and context produced from VirusTotal.

    Args:
        domain (str): The domain to check.
    Returns:
        dict: The response from VirusTotal, or an error message if the request fails.
    """

    response = requests.get(f"{base_url}domains/{domain}", headers=auth_header)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": f"Failed to retrieve data for domain {domain}. Status code: {response.status_code}"
        }