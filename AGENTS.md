# AGENTS.md — caddy-body-matcher

Caddy v2 plugin providing `http.matchers.body` (request body matching) and
`http.handlers.body_vars` (body field extraction into placeholders). Single
Go package, no subdirectories.

## Build & Test Commands

```bash
# Run all tests
go test ./...

# Run all tests with verbose output
go test -v ./...

# Run a single test by name (supports regex)
go test -v -run TestContains_Match ./...
go test -v -run TestJSON ./...           # runs all tests matching "TestJSON"

# Run tests with race detector (there are concurrency tests)
go test -race ./...

# Build the plugin into a Caddy binary (requires xcaddy)
xcaddy build --with github.com/erfianugrah/caddy-body-matcher

# Tidy dependencies
go mod tidy

# Vet
go vet ./...
```

There is no Makefile, no CI pipeline, and no linter config. Always run
`go vet ./...` before committing.

## Project Layout

```
bodymatcher.go        # All production code (~935 lines, single file)
bodymatcher_test.go   # All tests (~1683 lines, single file)
go.mod                # Go 1.25.0, module github.com/erfianugrah/caddy-body-matcher
```

Everything lives in package `bodymatcher`. Tests use the same package
(not `bodymatcher_test`) so they can access unexported symbols.

## Code Style

### Imports

Two groups separated by a blank line:
1. Standard library (alphabetical)
2. Third-party (alphabetical)

```go
import (
    "bytes"
    "encoding/json"
    "fmt"

    "github.com/caddyserver/caddy/v2"
    "go.uber.org/zap"
)
```

### Naming

- **Types:** PascalCase — `MatchBody`, `BodyVars`
- **Exported methods:** Follow Caddy interfaces — `CaddyModule()`, `Provision()`,
  `Validate()`, `Match()`, `ServeHTTP()`, `UnmarshalCaddyfile()`
- **Unexported helpers:** camelCase — `readBody()`, `matchJSON()`, `parseSize()`,
  `resolveJSONPath()`, `jsonValueToString()`
- **Constants:** camelCase — `defaultMaxSize`
- **JSON struct tags:** snake_case — `json:"max_size,omitempty"`,
  `json:"json_path,omitempty"`
- **Test functions:** `TestCategory_Scenario` — e.g. `TestContains_Match`,
  `TestJSON_EqNoMatch`, `TestBodyVars_JSONSingleField`

### Method Receivers

- **Value receivers** for read-only methods: `func (m MatchBody) Match()`,
  `func (bv BodyVars) ServeHTTP()`
- **Pointer receivers** for mutating methods: `func (m *MatchBody) Provision()`,
  `func (bv *BodyVars) Validate()`

### Error Handling

- Wrap errors with `fmt.Errorf("context: %w", err)` — always use `%w` for wrapping.
- Validation methods return descriptive errors:
  `fmt.Errorf("body matcher requires at least one match criterion")`
- In `Match()` / `ServeHTTP()`, read errors log at Debug level and return
  `false` / continue gracefully — never propagate runtime I/O errors upward.
- Use early returns: `if r.Body == nil || r.Body == http.NoBody { return false }`

### Interface Guards

Compile-time interface checks at the bottom of `bodymatcher.go`:
```go
var (
    _ caddy.Module             = (*MatchBody)(nil)
    _ caddy.Provisioner        = (*MatchBody)(nil)
    _ caddyhttp.RequestMatcher = (*MatchBody)(nil)
    // ... etc
)
```
Always add these when implementing a new Caddy interface.

### Struct Organization

Group struct fields by category with section comments:
```go
// --- Raw body matching ---
Contains  string `json:"contains,omitempty"`
// --- JSON field matching ---
JSONPath  string `json:"json_path,omitempty"`
```

Use Unicode box-drawing dividers for major sections:
```go
// ─── BodyVars Handler ───────────────────────────────────────────────
```

### Body Handling Pattern

Both modules share `readRequestBody(r, maxSize)` which:
1. Reads via `io.LimitReader` capped at `maxSize + 1` (to detect overflow)
2. Re-wraps `r.Body` with `io.NopCloser(io.MultiReader(...))` so downstream
   handlers still see the full body
3. Returns truncated buffer for local processing

## Testing Conventions

- Standard `testing` package only — no testify, no gomock.
- Table-driven tests with `t.Run()` subtests for utility functions
  (`TestParseSize`, `TestResolveJSONPath`, `TestJsonValueToString`).
- Individual `TestXxx` functions for matcher/handler behavior tests.
- Test helpers defined at the top of the test file:
  - `newRequest(body string)` / `newRequestBytes(body []byte)` — create POST requests
  - `testContext()` — create a `caddy.Context` for provisioning
  - `mustProvision(t, m)` / `mustProvisionBodyVars(t, bv)` — provision or fail
  - `newVarsRequest(body string)` — request with Caddy variable table in context
  - `noopHandler{}` — no-op `caddyhttp.Handler` for ServeHTTP tests
- Concurrency tests exist (50 goroutines) — always run `go test -race` to
  catch data races.

## Caddy Module Pattern

Every module follows:
1. `init()` — register with `caddy.RegisterModule()`
2. `CaddyModule()` — return module ID and constructor
3. `Provision(ctx caddy.Context)` — compile regexes, set defaults, get logger
4. `Validate()` — check config invariants (mutually exclusive options, required fields)
5. `Match(r)` / `ServeHTTP(w, r, next)` — runtime logic
6. `UnmarshalCaddyfile(d)` — parse both inline and block Caddyfile syntax

## Key Design Rules

- Only **one match type** per `MatchBody` instance (contains/eq/starts_with/
  ends_with/regex/json/form). Compose multiple via Caddy named matchers.
- Default `max_size` is 13 MiB (matches Coraza WAF `request_body_limit`).
- `eq` on truncated body always returns `false`.
- JSON path uses dot-notation; leading dot is optional. Array indices are
  numeric path segments (`.items.0.type`).
- Form parsing uses `url.ParseQuery()` directly — no content-type check.
