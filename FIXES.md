# FIXES.md — caddy-body-matcher code review findings

Code review conducted from the perspective of a reverse proxy engineer,
network engineer, and white hat security researcher. Findings are ordered
by priority. The ecosystem context (caddy-compose, caddy-policy-engine,
caddy-ddos-mitigator) is taken into account throughout.

All tests pass (`go test -race ./...`), `go vet` is clean, no data races
detected.

---

## Critical

### 1. Rate-limit key vanishes on oversized body (ecosystem bypass)

**Status: FIXED** — Warn log on truncated JSON parse + `body_json._truncated` sentinel variable set in BodyVars.ServeHTTP. Policy engine also fixed to fall back to client IP on empty rate-limit key.

**File:** `bodymatcher.go:699-711`

When the request body exceeds `MaxSize`, `readRequestBody` returns a
truncated buffer. `json.Unmarshal` on truncated JSON fails, the
`if err == nil` gate silently skips variable extraction, and no
`body_json.*` placeholders get set.

In the broader stack, `caddy-policy-engine` uses these placeholders as
rate-limit keys (e.g., `{http.vars.body_json.user.api_key}`). An attacker
can prepend junk padding to push a JSON body past 13 MiB, causing the
rate-limit key to resolve to empty string. Depending on how the policy
engine handles an empty key, this either disables the rate limit entirely
or collapses all traffic onto a single bucket.

**Attack scenario:**
```
POST /api/action HTTP/1.1
Content-Type: application/json
Content-Length: 14000000

{"padding":"AAAA...(13+ MiB)...AAAA","user":{"api_key":"sk-target"}}
```

The `body_vars` handler reads 13 MiB, truncates, `json.Unmarshal` fails,
`body_json.user.api_key` is never set, rate limit is bypassed.

**Recommendation:**
- Log at Warn level when JSON parse fails on a body that was truncated
  (i.e., original body exceeded MaxSize). This gives operators immediate
  visibility.
- Verify what `caddy-policy-engine` does when a rate-limit key placeholder
  resolves to empty string. If it falls through or uses a permissive
  fallback, that's a separate bug in the policy engine.
- Consider whether `BodyVars` should set a sentinel variable like
  `body_json._truncated = "true"` when the body exceeds MaxSize, so
  downstream rules can detect and handle this case explicitly.

**Affected code:**
```go
// bodymatcher.go:699-711
if len(bv.JSONPaths) > 0 && len(buf) > 0 {
    var root interface{}
    if err := json.Unmarshal(buf, &root); err == nil {
        // ... silently skipped on truncated body
    }
}
```

---

### 2. No regex pattern size limit

**Status: FIXED** — `maxRegexLen = 4096` constant added; Provision() rejects patterns exceeding this limit for body regex, json_regex, and form_regex.

**File:** `bodymatcher.go:128`, `137`, `146`

`regexp.Compile()` accepts arbitrary patterns from Caddyfile config or
the Caddy admin API. Go's RE2 engine guarantees linear-time matching
(no catastrophic backtracking), so this is not a classic ReDoS vector.
However, matching cost is `O(pattern_size * body_size)`. A pathologically
complex pattern matched against a 13 MiB body can still consume
significant CPU time.

In this stack, regex patterns can originate from:
- Caddyfile (operator-controlled, lower risk)
- Caddy admin API / JSON config (potentially writable by wafctl)
- Policy engine rules generated from OWASP CRS (controlled, but large)

**Recommendation:**
- Add a compile-time size limit on regex patterns (e.g., reject patterns
  longer than 4096 bytes) in `Provision()`:
  ```go
  const maxRegexLen = 4096
  if len(m.Regex) > maxRegexLen {
      return fmt.Errorf("body regex pattern too long (%d bytes, max %d)", len(m.Regex), maxRegexLen)
  }
  ```
- Document that regex matching cost scales linearly with body size.

---

## High

### 3. MaxSize=0 silently becomes 13 MiB — no way to express "zero"

**Status: OPEN** — Retained current behavior (zero → default). Explicit zero is a nonsensical config value; the upper bound fix (#5) addresses the OOM risk.

**File:** `bodymatcher.go:122-124`, `664-666`

`Provision()` treats `MaxSize == 0` as "not set" and overwrites it with
the 13 MiB default:

```go
if m.MaxSize == 0 {
    m.MaxSize = defaultMaxSize
}
```

A user who explicitly sets `max_size 0` (via JSON config — the Caddyfile
parser would produce `parseSize("0")` = 0) intending "don't read the
body" gets 13 MiB silently applied instead.

Combined with `Validate()` at line 158, which only rejects `MaxSize < 0`
but not `MaxSize == 0`, this creates a configuration footgun where
explicit zero is indistinguishable from unset.

**Recommendation (pick one):**
- **Option A:** Use a pointer field `MaxSize *int64` so nil = unset, 0 = explicit zero.
- **Option B:** Use a sentinel: treat `-1` as "use default" and allow 0 to mean "zero bytes" (which would effectively disable the matcher — `Match()` returns false on empty buffer). This requires changing the `< 0` check in `Validate()`.
- **Option C:** Reject `MaxSize == 0` in `Validate()` with a clear error message. Simplest fix if zero is never a useful value.

---

### 4. Truncation detection is coupled to buffer length — fragile

**Status: FIXED** — `readRequestBody` now returns `bodyReadResult` struct with explicit `truncated bool` flag, decoupling callers from buffer-length arithmetic.

**File:** `bodymatcher.go:242`, `752-754`

`Match()` infers truncation from `int64(len(buf)) >= m.MaxSize`. This
works only because `readRequestBody` guarantees that on overflow it
returns exactly `buf[:maxSize]`. If `readRequestBody` ever returns a
shorter buffer (e.g., due to a partial network read that happens to equal
`maxSize` bytes exactly), this check would produce a false positive.

The two functions are tightly coupled through an implicit contract about
buffer length semantics that isn't documented or enforced by types.

**Recommendation:**
Return a struct or a `truncated bool` flag from `readRequestBody`:

```go
type bodyReadResult struct {
    buf       []byte
    truncated bool
}

func readRequestBody(r *http.Request, maxSize int64) (bodyReadResult, error) {
    // ...
    if int64(len(buf)) > maxSize {
        r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
        return bodyReadResult{buf: buf[:maxSize], truncated: true}, nil
    }
    r.Body = io.NopCloser(bytes.NewReader(buf))
    return bodyReadResult{buf: buf, truncated: false}, nil
}
```

This makes the truncation signal explicit and decouples callers from
buffer-length arithmetic.

---

### 5. No MaxSize upper bound — unbounded heap allocation

**Status: FIXED** — `maxAllowedSize = 256 MiB` constant; Validate() rejects MaxSize exceeding this for both MatchBody and BodyVars.

**File:** `bodymatcher.go:158`, `671`

`Validate()` rejects negative `MaxSize` but has no ceiling. A config of
`max_size 1tb` causes `io.ReadAll` in `readRequestBody` to attempt a
~1 TiB heap allocation, OOM-killing Caddy and taking down the entire
edge stack.

Since this is the internet-facing reverse proxy, an OOM crash means all
proxied services go down simultaneously.

**Recommendation:**
Add an upper bound in `Validate()`:

```go
const maxAllowedSize = 256 * 1024 * 1024 // 256 MiB
if m.MaxSize > maxAllowedSize {
    return fmt.Errorf("max_size %d exceeds maximum allowed %d (256 MiB)", m.MaxSize, maxAllowedSize)
}
```

Choose a ceiling that's generous enough for legitimate use (file uploads
shouldn't go through body matching anyway) but prevents accidental or
malicious OOM. 256 MiB or even 64 MiB is likely sufficient. The default
13 MiB already matches Coraza WAF's `request_body_limit`.

---

## Medium

### 6. Per-request `[]byte` allocations from string fields

**Status: FIXED** — String match values pre-converted to `[]byte` during Provision() and stored as `containsBytes`, `equalsBytes`, `startsWithBytes`, `endsWithBytes` fields.

**File:** `bodymatcher.go:255-261`

On every request, string match values are converted to `[]byte`:

```go
case m.Contains != "":
    return bytes.Contains(buf, []byte(m.Contains))
case m.Equals != "":
    return bytes.Equal(buf, []byte(m.Equals))
case m.StartsWith != "":
    return bytes.HasPrefix(buf, []byte(m.StartsWith))
case m.EndsWith != "":
    return bytes.HasSuffix(buf, []byte(m.EndsWith))
```

Each `[]byte(someString)` allocates a new byte slice on the heap. At the
request volumes of an internet-facing edge proxy, this adds GC pressure.

**Recommendation:**
Pre-convert to `[]byte` during `Provision()` and store as unexported fields:

```go
type MatchBody struct {
    // ... existing fields ...
    containsBytes   []byte
    equalsBytes     []byte
    startsWithBytes []byte
    endsWithBytes   []byte
}

func (m *MatchBody) Provision(ctx caddy.Context) error {
    // ... existing code ...
    if m.Contains != "" {
        m.containsBytes = []byte(m.Contains)
    }
    // ... etc for each field
}
```

Then in `Match()`:
```go
case m.Contains != "":
    return bytes.Contains(buf, m.containsBytes)
```

Zero per-request allocations for the match comparison.

---

### 7. Caddyfile parser silently ignores trailing arguments

**Status: FIXED** — All single-value operators (contains, eq, starts_with, ends_with, regex) now reject unexpected trailing arguments.

**File:** `bodymatcher.go:478-501`

After parsing an operator's required arguments, the parser does not check
for unexpected trailing tokens. For example:

```caddyfile
body contains "foo" "bar" "extra"
```

The parser consumes `"foo"` for `Contains` and silently ignores `"bar"`
and `"extra"`. This can mask configuration errors where the user intended
a different operator or syntax.

Same issue applies to all single-value operators (eq, starts_with,
ends_with, regex) and to json/form operators that could have extra
trailing tokens.

**Recommendation:**
After each operator parse, check for unexpected arguments:

```go
case "contains":
    if !d.NextArg() {
        return d.Errf("body contains requires a value")
    }
    m.Contains = d.Val()
    if d.NextArg() {
        return d.Errf("unexpected argument after contains value: %s", d.Val())
    }
```

Apply to all operator cases in `parseOperator()`.

---

## Low

### 8. Form and JSON matching are Content-Type blind (by design)

**Status: OPEN** — By design; documentation improvement only.

**File:** `bodymatcher.go:380`, `311`

Both `matchForm()` and `matchJSON()` parse the body without checking
`Content-Type`. The README documents this as intentional ("No content-type
filtering — scoping by content-type is done via other Caddy matchers"),
but it's a footgun for WAF rule authors.

`url.ParseQuery` is particularly lenient — it will "successfully" parse
almost any input, potentially producing unexpected field matches on
non-form bodies.

**Recommendation:**
No code change needed, but add a prominent note in the README and godoc:

```
WARNING: Body matchers do not check Content-Type. In WAF rules, always
pair body matchers with a Content-Type header matcher to prevent false
positives:

@json_action {
    header Content-Type application/json*
    body json .action "delete"
}
```

---

### 9. `parseSize` treats GB/MB/KB as binary (1024-based)

**Status: OPEN** — Low priority; unlikely to cause real issues.

**File:** `bodymatcher.go:582-596`

`gb` maps to `1024^3` (GiB), `mb` maps to `1024^2` (MiB), `kb` maps to
`1024`. Standard convention (SI/IEC) is that GB/MB/KB are decimal
(1000-based) while GiB/MiB/KiB are binary (1024-based).

Caddy's own `caddy.ParseDuration` and related utilities follow standard
conventions. This inconsistency could confuse users, though the practical
difference is small (<5% for MB vs MiB).

**Recommendation:**
Either:
- Follow SI conventions (GB=10^9, MB=10^6, KB=10^3) and keep GiB/MiB/KiB
  as binary, or
- Document in the Caddyfile syntax help that all size units are binary
  (1 KB = 1024 bytes).

Low priority — unlikely to cause real issues at the sizes used in
practice.

---

### 10. No test for `MaxSize=0` behavior

**Status: OPEN** — Deferred; current behavior (zero → default) is documented and validated by #5.

There is no test that sets `MaxSize: 0` in a JSON config (bypassing
Caddyfile parsing) and verifies the resulting behavior. Given issue #3
above, this is an untested edge case where the user's explicit intent is
silently overwritten.

**Recommendation:**
Add a test:

```go
func TestMaxSize_ZeroIsOverwrittenToDefault(t *testing.T) {
    m := &MatchBody{Contains: "test", MaxSize: 0}
    ctx, cancel := testContext()
    defer cancel()
    m.Provision(ctx)
    if m.MaxSize != defaultMaxSize {
        t.Errorf("expected MaxSize to be overwritten to default, got %d", m.MaxSize)
    }
}
```

This documents the current behavior even if it's not the desired behavior.

---

### 11. No concurrent test for `BodyVars.ServeHTTP`

**Status: OPEN** — Low priority; requests are not shared across goroutines in real Caddy usage.

Concurrency tests exist for `MatchBody.Match()` (3 tests with 50
goroutines each) but not for `BodyVars.ServeHTTP()`. Since `ServeHTTP`
uses a value receiver and doesn't mutate shared state, it's likely safe,
but the body re-wrapping via `r.Body` assignment could theoretically race
if the same request is passed to multiple goroutines.

**Recommendation:**
Add a concurrent BodyVars test parallel to the existing Match concurrency
tests. Low priority since requests are not shared across goroutines in
real Caddy usage.

---

### 12. `jsonValueToString` loses precision on large integers

**Status: OPEN** — Low priority; requires API change to json.Decoder with UseNumber().

**File:** `bodymatcher.go:358-362`

```go
case float64:
    if val == float64(int64(val)) {
        return strconv.FormatInt(int64(val), 10)
    }
```

JSON numbers exceeding 2^53 (e.g., snowflake IDs like `9007199254740993`)
lose precision when parsed as `float64` via `encoding/json` with
`interface{}` unmarshaling. The value is silently rounded.

This is a fundamental limitation of Go's `encoding/json` when
unmarshaling into `interface{}`, not specific to this code.

**Recommendation:**
If the policy engine or rate limiter ever needs to match on large numeric
IDs, switch to `json.Decoder` with `UseNumber()`:

```go
dec := json.NewDecoder(bytes.NewReader(body))
dec.UseNumber()
var root interface{}
dec.Decode(&root)
```

Then handle `json.Number` in `jsonValueToString`:
```go
case json.Number:
    return val.String()
```

Low priority — most real-world JSON path matching is against string
values, not large integers.

---

### 13. No test for deeply nested JSON paths

**Status: OPEN** — Low priority; config-time only, not exploitable at runtime.

`resolveJSONPathFromRoot` iterates over `strings.Split(dotPath, ".")`
segments. A malicious config with a very deep path (e.g., 10,000 dot
segments) would iterate 10,000 times. This is config-time only and not
exploitable at runtime, but a test would document the behavior.

---

### Additional Fix: `compiledRegex` nil guard

**Status: FIXED** — Nil guard added to `compiledRegex` check in `Match()` (now uses `m.Regex != "" && m.compiledRegex != nil`) for consistency with `compiledJSONRegex` and `compiledFormRegex`. (Identified in caddy-compose FIXES.md L-2.)

---

## Ecosystem Integration Notes

These are not bugs in caddy-body-matcher specifically, but observations
about how it interacts with the rest of the ergo stack.

### Body reading duplication across the handler chain

Both `caddy-body-matcher` (`body_vars`) and `caddy-policy-engine` read
and re-wrap request bodies independently. When both are in the Caddy
handler chain (which they are — `body_vars` runs before `policy_engine`),
the body is read, buffered, and re-wrapped twice per request.

For a 13 MiB body, that's ~26 MiB of heap allocation per request plus
a growing `MultiReader` wrapper chain.

**Future consideration:** A shared "body cache" pattern where the first
handler stores the buffered body in a context variable
(`caddyhttp.SetVar(r.Context(), "body_cache", buf)`) and subsequent
handlers check for the cached copy before re-reading. This would require
a small coordination protocol between the plugins.

### Variable namespace is convention-only

`BodyVars` sets variables with `body_json.` and `body_form.` prefixes.
If another middleware sets variables with the same prefix, there's a
silent collision. There's no registry or enforcement of variable
namespaces in Caddy.

### Rate-limit bypass verification needed

The highest-priority finding (#1) depends on how `caddy-policy-engine`
handles rate-limit rules when the key placeholder resolves to empty
string. Three possible behaviors:

1. **Rule doesn't fire** (key is empty, no bucket matched) — bypass.
2. **All traffic collapses to a single "" bucket** — DoS against all
   users sharing the empty-key bucket.
3. **Fallback to IP-based key** — safe, but only if explicitly
   configured.

Verify which behavior the policy engine implements and whether the wafctl
rule generator produces rules with fallback keys.
