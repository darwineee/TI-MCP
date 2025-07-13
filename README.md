# Threat Intelligence MCP Server

A Model Context Protocol (MCP) server providing threat intelligence tools to help AI assistants with security investigations and analysis.

## Features

- **VirusTotal Integration**: Check file hashes against the VirusTotal database
- **FastMCP Framework**: Built on the FastMCP framework for easy extensibility
- **Docker Support**: Containerized deployment ready

## Prerequisites

- Python 3.13+
- VirusTotal API key (free account available at [VirusTotal](https://www.virustotal.com/))

## Installation

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd TI-MCP
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and add your VirusTotal API key
   echo "VT_API_KEY=your_virustotal_api_key_here" > .env
   ```

5. **Run the server**
   ```bash
   python main.py
   ```

### Docker Deployment

1. **Build the Docker image**
   ```bash
   docker build -t ti-mcp-server .
   ```

2. **Run the container**
   ```bash
   # With environment file
   docker run -p 8081:8081 --env-file .env ti-mcp-server
   
   # Or with environment variable
   docker run -p 8081:8081 -e VT_API_KEY=your_api_key ti-mcp-server
   ```

## API Endpoints

### Health Check
- **Endpoint**: `GET /health`
- **Description**: Check if the server is running
- **Response**: `{"status": "healthy"}`

### MCP Tools

The server provides the following MCP tools through the VirusTotal integration:

#### check_hash
- **Description**: Check a file hash against VirusTotal database
- **Parameters**:
  - `hash` (string): MD5, SHA1, or SHA256 file hash
- **Returns**: VirusTotal analysis results including detection ratios and scan details

## Usage Examples

### Using with MCP Client

```python
# Example MCP client usage
import asyncio
from mcp import ClientSession

async def check_file_hash():
    async with ClientSession("http://localhost:8081") as session:
        result = await session.call_tool("virus_total_check_hash", {
            "hash": "d41d8cd98f00b204e9800998ecf8427e"
        })
        print(result)

asyncio.run(check_file_hash())
```

## Development

### Adding New Tools

1. Create a new module in the project directory
2. Define your FastMCP instance with tools
3. Import and register it in `main.py`:

```python
from your_module import your_mcp
await main_mcp.import_server(your_mcp, prefix="your_prefix")
```

### Testing

#### Health Check
```bash
# Test if the server is running
curl http://localhost:8081/health
```

#### MCP Inspector Testing
The easiest way to test the MCP server is using the official MCP Inspector:

```bash
# Install MCP Inspector (requires Node.js)
npx @modelcontextprotocol/inspector

# When prompted, enter your server URL:
# http://localhost:8081

# Or run directly with the URL:
npx @modelcontextprotocol/inspector http://localhost:8081
```

The MCP Inspector will:
- Connect to your MCP server
- Show available tools (like `virus_total_check_hash`)
- Allow you to test tools interactively
- Display tool schemas and responses

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Open an issue on GitHub
- Check the [FastMCP documentation](https://github.com/jlowin/fastmcp)
- Review [VirusTotal API documentation](https://developers.virustotal.com/reference)

## Changelog

### v1.0.0
- Initial release
- VirusTotal hash checking functionality
- Docker support