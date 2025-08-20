# OAuth2 Client Test Tool

A command-line tool for testing OAuth2 authorization code flow with PKCE (Proof Key for Code Exchange) support. This tool helps validate OAuth2 implementations by performing a complete authorization code flow and testing protected endpoints.

## Requirements

- Go 1.25.0 or later
- A web browser for authorization

## Install

```
go install github.com/chet-wynn-cookieai/oauth2client
```

## Usage

### Basic Usage

```bash
oauth2client start \
    --client-id "your-client-id" \
    --client-secret "your-client-secret" \
    --tenant "https://your-tenant.example.com" \
    --scope "demo:write"
```

### Default Configuration (Tenant1)

```bash
./oauth2client start \
    --client-id "your-client-id" \
    --client-secret "your-client-secret" \
    --scope "demo:write"
```

This uses the default tenant URL: `https://tenant1.cookieai.test:8081`

### Command Options

- `--client-id` (required): OAuth2 client ID
- `--client-secret` (required): OAuth2 client secret  
- `--tenant`: Tenant URL for the OAuth2 server (default: `https://tenant1.cookieai.test:8081`)
- `--redirect_uri`: OAuth2 redirect URI (default: `http://localhost:18181/callback`)
- `--scope`: OAuth2 scope (default: `demo:write`)
- `-v, --verbose`: Enable debug logging (use `-vv` for trace level)

### Help

```bash
./oauth2client --help
./oauth2client start --help
```

## How It Works

1. **Authorization**: Opens a browser to the OAuth2 authorization URL
2. **Callback**: Starts a local server on port 18181 to receive the authorization code
3. **Token Exchange**: Exchanges the authorization code for an access token using PKCE
4. **Testing**: Tests protected endpoints:
   - `/oauth/userinfo` - UserInfo endpoint
   - `/api/private/system` - System endpoint

## OAuth2 Endpoints

The tool expects the following OAuth2 endpoints on your server:

- **Authorization**: `/oauth/authorize`
- **Token**: `/oauth/token` 
- **UserInfo**: `/oauth/userinfo`
- **System Test**: `/api/private/system`

## Security Features

- **PKCE (RFC 7636)**: Uses Proof Key for Code Exchange to prevent authorization code interception attacks
- **State Parameter**: Includes CSRF protection via state parameter
- **Secure Token Handling**: Proper token storage and usage patterns

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `golang.org/x/oauth2` - OAuth2 client library
- `github.com/sirupsen/logrus` - Structured logging
- `github.com/pkg/errors` - Error handling
- `github.com/google/uuid` - UUID generation

## Output

The tool provides colorized output showing:
- Configuration details
- Authorization URL
- Token information (access token, refresh token, expiry, scopes)
- Endpoint test results
- Success/failure status for each step

## Example Output

```
🚀 Starting OAuth2 client test
📍 Tenant: https://tenant1.cookieai.test:8081
🔑 Client ID: your-client-id
🔗 Redirect URI: http://localhost:18181/callback
🎯 Scope: demo:write

🔐 Please open the following URL in your browser to authorize:
https://tenant1.cookieai.test:8081/oauth/authorize?...

⏳ Waiting for authorization callback...
✅ Authorization code received

🔑 Token Details:
  Access Token: eyJ0eXAiOiJKV1Q...
  Refresh Token: def502001a8b...
  Expiry: 2024-01-01 12:00:00
  Scopes: demo:write
  ID Token: present
  Token Type: Bearer

🎯 Authentication successful!

=== Testing UserInfo endpoint ===
📋 User Info Response: {"sub":"user123","name":"Test User"}
✅ UserInfo test passed

=== Testing Users:Me endpoint ===
👤 System Response: {"status":"ok","user":"authenticated"}
✅ Users:Me test passed

🎉 OAuth2 client test completed successfully
```