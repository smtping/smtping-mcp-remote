# SMTPing remote MCP server

Remote MCP server for [SMTPing](https://smtping.com) email verification, at:

```
https://mcp.smtping.com/mcp
```

Transport: Streamable HTTP (stateless, JSON responses). Auth: OAuth 2.1 with PKCE and dynamic client registration; the user pastes their SMTPing API key on the SMTPing consent page. Clients without OAuth can send the key in an `X-API-Key` header.

## Tools

| Tool | What it does | Cost |
| --- | --- | --- |
| `verify_email` | Verifies one address: status plus band (safe, avoid, judgement) | 1 credit |
| `verify_list` | Bulk job, deduplicated, up to 100,000 addresses | 1 credit per unique address |
| `get_bulk_job` | Progress and results of a bulk job | free |
| `check_threat` | One lookup in the spamtrap, disposable, spambot or complainer list | 1 credit |
| `get_credits` | Remaining credits and plan | free |

Unknown results are never charged; 25 free credits per day per account.

## Connect

- **Claude**: Settings > Connectors > Add custom connector, URL `https://mcp.smtping.com/mcp`.
- **ChatGPT**: Settings > Apps & Connectors > Create, URL `https://mcp.smtping.com/mcp`, authentication OAuth.
- **Other clients** (Cursor, VS Code, Windsurf): add a remote server with the same URL.

For a local stdio server, use [`@smtping/mcp`](https://github.com/smtping/smtping-mcp).

## Security

- The API key is checked against SMTPing, then encrypted (AES-256-GCM) inside the access and refresh tokens. The server stores nothing.
- Access tokens last 7 days, refresh tokens 1 year. Rotating the API key in SMTPing revokes every token built from it.
- PKCE S256 is required; the consent page cannot be framed.

## Deploy (Netlify)

1. New site from this repository; build settings come from `netlify.toml`.
2. Environment variable `TOKEN_SECRET`: a random string of 32 characters or more. Changing it signs every user out.
3. Optional `PUBLIC_URL` = `https://mcp.smtping.com`.
4. Custom domain `mcp.smtping.com` (CNAME to the Netlify site).

## Links

- Website: [smtping.com](https://smtping.com)
- API docs: [smtping.com/docs](https://smtping.com/docs)
- Local MCP server: [smtping/smtping-mcp](https://github.com/smtping/smtping-mcp)
- Support: support@smtping.com
- Blog: [SMTPedia](https://smtpedia.com)
