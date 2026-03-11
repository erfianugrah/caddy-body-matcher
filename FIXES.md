# Code Review Fixes

This document tracks all issues identified during the code review and their resolution status.

## Progress

- [x] Fix 1: `parseSize` uses `strings.TrimRight` instead of `strings.TrimSuffix`
- [x] Fix 2: Dead/misleading code in `matchJSON`
- [x] Fix 3: Redundant JSON unmarshal in `BodyVars.ServeHTTP`
- [x] Fix 4: Duplicated `readBody` implementation
- [x] Fix 5: `parseSize` accepts negative values silently
- [x] Fix 6: Error wrapping uses `%v` instead of `%w`
- [x] Fix 7: No tests for Caddyfile unmarshaling
- [x] Fix 8: No tests for `parseOperator` error paths
- [x] Fix 9: No concurrency/race condition test
- [x] Update README to reflect changes

---

## Bug Fixes

### 1. `parseSize` uses `strings.TrimRight` instead of `strings.TrimSuffix`

**File:** `bodymatcher.go:591-602`
**Severity:** Medium (latent bug)

`strings.TrimRight(s, "mib")` removes any *characters* in the set `{m, i, b}` from the right
side of the string, not the substring `"mib"`. This is fundamentally different from removing a
suffix. While current numeric inputs happen to survive (digits 0-9 are not in any cutset), the
logic is incorrect and fragile:

- An input like `"11gib"` works by accident: TrimRight strips `b`, `i`, `g` character-by-character,
  leaving `"11"`.
- But hypothetical future suffixes or non-standard inputs could break unpredictably.

**Fix:** Replace all `strings.TrimRight` calls with `strings.TrimSuffix`, matching the suffix
that was detected by `strings.HasSuffix`. Check longer suffixes first (`gib` before `gb`) to
avoid partial matches.

---

### 2. Dead/misleading code in `matchJSON`

**File:** `bodymatcher.go:303`
**Severity:** Low (code clarity)

```go
return m.JSONOp == "exists" && false // field not found
```

This expression always evaluates to `false` regardless of `m.JSONOp`. The `&& false` makes
the left side irrelevant. This is confusing dead code.

**Fix:** Replace with `return false` and a clear comment explaining that the field was not found
(including for the `exists` operation).

---

### 3. Redundant JSON unmarshal in `BodyVars.ServeHTTP`

**File:** `bodymatcher.go:700-711`
**Severity:** Medium (performance)

The code unmarshals JSON into `root` on line 701 just to check if parsing succeeds, then calls
`resolveJSONPath()` which unmarshals the exact same `[]byte` body *again* for every configured
JSON path. For N paths, this results in N+1 JSON parses instead of 1.

The `root` variable from line 700 is never actually used for field resolution.

**Fix:** Introduce a `resolveJSONPathFromRoot(root interface{}, dotPath string)` function that
operates on an already-parsed JSON value. Parse once in `ServeHTTP`, then call the from-root
resolver for each path. The existing `resolveJSONPath(body []byte, ...)` function is kept as a
convenience wrapper for callers that have raw bytes (like `MatchBody.matchJSON`).

---

### 4. Duplicated `readBody` implementation

**File:** `bodymatcher.go:275-297` and `bodymatcher.go:732-748`
**Severity:** Medium (code quality / DRY violation)

`MatchBody.readBody` and `BodyVars.readBody` are nearly identical — both read up to `MaxSize+1`
bytes, re-wrap the body for downstream, and truncate to `MaxSize`. Any bug fix or behavior change
must be applied in both places, which is error-prone.

**Fix:** Extract a shared `readRequestBody(r *http.Request, maxSize int64) ([]byte, error)` package-
level function. Both `MatchBody` and `BodyVars` delegate to it.

---

### 5. `parseSize` accepts negative values silently

**File:** `bodymatcher.go:586-609`
**Severity:** Low-Medium

`parseSize("-5mb")` returns `-5242880` without error. While `Validate()` catches negative
`MaxSize` downstream, the size parser itself should reject nonsensical values at parse time
for better error messages and defense in depth.

**Fix:** Add a check after parsing the integer: if the result is negative, return an error.

---

### 6. Error wrapping uses `%v` instead of `%w`

**File:** `bodymatcher.go` (multiple locations)
**Severity:** Low (idiomatic Go)

Errors are wrapped with `fmt.Errorf("...: %v", err)` instead of `fmt.Errorf("...: %w", err)`.
Using `%w` is idiomatic Go since 1.13 and enables callers to unwrap and inspect underlying errors
with `errors.Is()` and `errors.As()`.

**Fix:** Replace `%v` with `%w` for all error wrapping calls.

---

## Test Coverage Gaps

### 7. No tests for Caddyfile unmarshaling

**Severity:** High

`MatchBody.UnmarshalCaddyfile` and `BodyVars.UnmarshalCaddyfile` are the primary user-facing
configuration surfaces. They contain complex branching logic (inline vs. block syntax, 12+
operators, max_size parsing, error conditions) with zero test coverage.

**Fix:** Add comprehensive tests covering:
- Single-line syntax for each operator
- Block syntax with max_size
- Error cases (missing arguments, unknown operators, mixed inline + block)
- `BodyVars` single-field and block syntax

---

### 8. No tests for `parseOperator` error paths

**Severity:** Medium

The unknown operator path and missing-argument paths in `parseOperator` are not exercised.

**Fix:** Add tests for unknown operators and missing required arguments.

---

### 9. No concurrency/race condition test

**Severity:** Medium

Caddy matchers can be invoked concurrently. While the code appears race-free (Match uses a value
receiver, compiled regexes are read-only after Provision), this should be verified.

**Fix:** Add a test that exercises `Match` from multiple goroutines and ensure tests pass under
`go test -race`.

---

## README Updates

### 10. Update README to reflect changes

Update the README to fix the incorrect rate-limit placeholder example (double dot) and ensure
documentation stays consistent with any API changes from the fixes above.
