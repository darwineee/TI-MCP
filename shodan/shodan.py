from os import getenv
from fastmcp import FastMCP
import requests
from bs4 import BeautifulSoup

base_url = "https://www.shodan.io/host/"

shodan_mcp = FastMCP(
    name="Shodan MCP server",
    instructions="""
    Using the `search_ip` tool with an IP address to retrieve information about services found on that host.
    The response includes the IP address, last seen date, tags, general information, and open ports.
    """,
)

@shodan_mcp.tool
def search_ip(ip: str) -> dict:
    """
    Searches for a host by IP address and retrieves information about services found on that host.

    Args:
        ip (str): The IP address to search.
    Returns:
        dict: The response containing extracted information from Shodan.
    """
    response = requests.get(f"{base_url}{ip}")
    if response.status_code == 200:
        return extract_shodan_info(response.text)
    else:
        return {
            "error": f"Failed to retrieve data for IP '{ip}'. Status code: {response.status_code}"
        }

def extract_shodan_info(html_content) -> dict:
    # Parse HTML content
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Initialize dictionary to store extracted data
    extracted_data = {
        'ip_address': '',
        'last_seen': '',
        'tags': [],
        'general_info': {},
        'open_ports': []
    }
    
    # Extract IP Address
    ip_element = soup.find('h2', class_='host-title')
    if ip_element:
        extracted_data['ip_address'] = ip_element.get_text(strip=True)
    else:
        title_element = soup.find('title')
        if title_element:
            extracted_data['ip_address'] = title_element.get_text(strip=True)
    
    # Extract Last Seen
    last_seen_element = soup.find('h6', class_='grid-heading')
    if last_seen_element and 'Last Seen' in last_seen_element.get_text():
        extracted_data['last_seen'] = last_seen_element.find('span').get_text(strip=True).replace('Last Seen: ', '')
    
    # Extract Tags
    tags_div = soup.find('div', id='tags')
    if tags_div:
        tags = tags_div.find_all('a', class_='tag')
        extracted_data['tags'] = [tag.get_text(strip=True) for tag in tags]
    
    # Extract General Information
    general_div = soup.find('div', class_='card card-yellow card-padding')
    if general_div:
        grid_table = general_div.find('div', class_='grid-table')
        if grid_table:
            labels = grid_table.find_all('label')
            values = grid_table.find_all('div', recursive=False)[::2]  # Skip grid-border divs
            for label, value in zip(labels, values):
                key = label.get_text(strip=True)
                val = value.find('strong').get_text(strip=True) if value.find('strong') else value.get_text(strip=True)
                extracted_data['general_info'][key] = val
    
    # Extract Open Ports
    ports_div = soup.find('div', id='ports')
    if ports_div:
        ports = ports_div.find_all('a', class_='bg-primary')
        for port in ports:
            port_info = {'port': port.get_text(strip=True)}
            port_section = soup.find('h6', id=port.get_text(strip=True))
            if port_section:
                # Extract port details
                port_info['protocol'] = port_section.find('span').get_text(strip=True).split('/')[-1]
                # Extract banner (HTTP response)
                banner = port_section.find_next('div', class_='card card-padding banner')
                if banner:
                    port_info['banner'] = banner.get_text(strip=True)
                extracted_data['open_ports'].append(port_info)
    
    return extracted_data