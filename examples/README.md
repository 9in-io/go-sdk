# Examples

Small runnable programs that use the 9in Go SDK. Each reads its settings from `NINE_*`
environment variables.

| Folder | What it shows |
|---|---|
| [`webapp`](webapp) | Sign-in for a server-rendered app with `nine.WebApp`: `/nine/login`, `/nine/callback`, `/nine/logout`, a protected page and a call to your API with the user's access token |
| [`api`](api) | An API protected with `nine.RequireAuth` (hybrid verification) and a webhook endpoint that evicts revoked tokens |
| [`adapter`](adapter) | Keeping users in your own database: the adapter protocol endpoints over an in-memory user list |
| [`device`](device) | A CLI that signs in with the device flow |

```bash
# Regular Web App with http://localhost:3000/nine/callback as a callback URL
# and http://localhost:3000/ as a logout URL
export NINE_ISSUER=https://acme.9in.io NINE_CLIENT_ID=app_… NINE_CLIENT_SECRET=…
export NINE_SECRET="$(openssl rand -base64 32)" NINE_BASE_URL=http://localhost:3000
go run ./examples/webapp
```
