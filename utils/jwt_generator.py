from fastmcp.server.auth.providers.bearer import RSAKeyPair

# Generate a new key pair
key_pair = RSAKeyPair.generate()

# Generate a token
token = key_pair.create_token(
    subject="n8n-user",
    issuer="development-test",
    audience="ti-mcp-server",
    scopes=["read", "write"],
    expiration_seconds=15778476, # 6 months
)

print(f"Public Key:\n{key_pair.public_key}")
print(f"JWT: {token}")