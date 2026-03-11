# caddy-body-matcher

A Caddy plugin providing two modules for request body inspection:

- **`http.matchers.body`** — Match requests based on body content (raw, JSON, form-encoded)
- **`http.handlers.body_vars`** — Extract body field values as Caddy placeholders

## Installation

```bash
xcaddy build --with github.com/erfianugrah/caddy-body-matcher
```

## Matcher (`body`)

Match requests based on body content. One match type per matcher instance — compose multiple via Caddy named matcher blocks.

### Match Types

| Category | Caddyfile Syntax | Description |
|----------|-----------------|-------------|
| Raw contains | `body contains "string"` | Substring match |
| Raw equals | `body eq "string"` | Exact match |
| Raw prefix | `body starts_with "string"` | Prefix match |
| Raw suffix | `body ends_with "string"` | Suffix match |
| Raw regex | `body regex "pattern"` | RE2 regex match |
| JSON field eq | `body json .path "value"` | JSON dot-path exact match |
| JSON field contains | `body json_contains .path "value"` | JSON dot-path substring match |
| JSON field regex | `body json_regex .path "pattern"` | JSON dot-path regex match |
| JSON field exists | `body json_exists .path` | JSON field presence check |
| Form field eq | `body form field "value"` | URL-encoded form field exact match |
| Form field contains | `body form_contains field "value"` | Form field substring match |
| Form field regex | `body form_regex field "pattern"` | Form field regex match |

### Examples

```caddyfile
# Block requests containing a specific string
@has_secret body contains "password123"
respond @has_secret 403

# Match JSON field value
@admin body json .user.role "admin"
reverse_proxy @admin admin-backend:8080

# Match form field with regex
@suspicious body form_regex username "^(admin|root|test)$"
respond @suspicious 403

# Check if JSON field exists
@has_token body json_exists .auth.token
reverse_proxy @has_token auth-backend:8080

# Custom max body size (default: 13 MiB)
@large_body body {
    max_size 1mb
    contains "search term"
}
```

## Handler (`body_vars`)

Middleware that reads the request body and exposes configured field values as Caddy placeholders. Useful for rate limiting by body fields, logging, or conditional routing.

### Exposed Placeholders

- `{http.vars.body_json.<dotpath>}` — value from a JSON body field
- `{http.vars.body_form.<field>}` — value from a form-encoded field

### Examples

```caddyfile
# Extract multiple fields
body_vars {
    json .user.api_key
    json .tenant.id
    form action
    form token
    max_size 13mb
}

# Single-field shorthand
body_vars json .user.api_key
body_vars form action

# Use extracted values as rate limit keys
body_vars json .user.api_key
rate_limit {
    key {http.vars.body_json.user.api_key}
    events 100
    window 1m
}
```

## Design Notes

- **Body buffering** — reads once via `io.LimitReader`, re-wraps `r.Body` with `io.MultiReader` so downstream handlers still see the full body
- **Default max_size: 13 MiB** — configurable via `max_size` directive
- **JSON path resolution** — dot-notation via `encoding/json`, supports array indices as numeric segments (e.g., `.items.0.type`)
- **No content-type filtering** — scoping by content-type is done via other Caddy matchers

## License

MIT
