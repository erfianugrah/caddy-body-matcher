package bodymatcher

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// --- Helpers ---

func newRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	return r
}

func newRequestBytes(body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	return r
}

// testContext creates a caddy.Context suitable for testing.
// Returns the context and a cancel function that must be deferred.
func testContext() (caddy.Context, context.CancelFunc) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	return ctx, cancel
}

func mustProvision(t *testing.T, m *MatchBody) {
	t.Helper()
	if m.MaxSize == 0 {
		m.MaxSize = defaultMaxSize
	}
	ctx, cancel := testContext()
	defer cancel()
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
}

// --- Raw Body: Contains ---

func TestContains_Match(t *testing.T) {
	m := &MatchBody{Contains: "password"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"user":"admin","pass":"password123"}`)) {
		t.Error("expected match for body containing 'password'")
	}
}

func TestContains_NoMatch(t *testing.T) {
	m := &MatchBody{Contains: "secret"}
	mustProvision(t, m)

	if m.Match(newRequest(`{"user":"admin","pass":"password123"}`)) {
		t.Error("expected no match for body not containing 'secret'")
	}
}

func TestContains_EmptyBody(t *testing.T) {
	m := &MatchBody{Contains: "anything"}
	mustProvision(t, m)

	if m.Match(newRequest("")) {
		t.Error("expected no match for empty body")
	}
}

func TestContains_NilBody(t *testing.T) {
	m := &MatchBody{Contains: "anything"}
	mustProvision(t, m)

	r := httptest.NewRequest("GET", "/", nil)
	if m.Match(r) {
		t.Error("expected no match for nil body")
	}
}

// --- Raw Body: Equals ---

func TestEquals_Match(t *testing.T) {
	m := &MatchBody{Equals: "exact"}
	mustProvision(t, m)

	if !m.Match(newRequest("exact")) {
		t.Error("expected match for exact body")
	}
}

func TestEquals_NoMatch(t *testing.T) {
	m := &MatchBody{Equals: "exact"}
	mustProvision(t, m)

	if m.Match(newRequest("exact plus more")) {
		t.Error("expected no match for body with extra content")
	}
}

// --- Raw Body: StartsWith ---

func TestStartsWith_Match(t *testing.T) {
	m := &MatchBody{StartsWith: `{"action":`}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"action":"deploy","target":"prod"}`)) {
		t.Error("expected match for body starting with prefix")
	}
}

func TestStartsWith_NoMatch(t *testing.T) {
	m := &MatchBody{StartsWith: "BEGIN"}
	mustProvision(t, m)

	if m.Match(newRequest("something else")) {
		t.Error("expected no match")
	}
}

// --- Raw Body: EndsWith ---

func TestEndsWith_Match(t *testing.T) {
	m := &MatchBody{EndsWith: "</html>"}
	mustProvision(t, m)

	if !m.Match(newRequest("<html><body>test</body></html>")) {
		t.Error("expected match for body ending with suffix")
	}
}

func TestEndsWith_NoMatch(t *testing.T) {
	m := &MatchBody{EndsWith: "</xml>"}
	mustProvision(t, m)

	if m.Match(newRequest("<html><body>test</body></html>")) {
		t.Error("expected no match")
	}
}

// --- Raw Body: Regex ---

func TestRegex_Match(t *testing.T) {
	m := &MatchBody{Regex: `"role"\s*:\s*"admin"`}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"role": "admin", "name": "test"}`)) {
		t.Error("expected regex match")
	}
}

func TestRegex_NoMatch(t *testing.T) {
	m := &MatchBody{Regex: `"role"\s*:\s*"admin"`}
	mustProvision(t, m)

	if m.Match(newRequest(`{"role": "user", "name": "test"}`)) {
		t.Error("expected no regex match")
	}
}

func TestRegex_Invalid(t *testing.T) {
	m := &MatchBody{Regex: `[invalid`, MaxSize: defaultMaxSize}
	ctx, cancel := testContext()
	defer cancel()
	err := m.Provision(ctx)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

// --- MaxSize ---

func TestMaxSize_TruncatesBody(t *testing.T) {
	m := &MatchBody{Contains: "needle", MaxSize: 10}
	mustProvision(t, m)

	// Needle is at position 15, beyond max_size of 10
	if m.Match(newRequest("0123456789-----needle")) {
		t.Error("expected no match when needle is beyond max_size")
	}
}

func TestMaxSize_MatchWithinLimit(t *testing.T) {
	m := &MatchBody{Contains: "needle", MaxSize: 20}
	mustProvision(t, m)

	if !m.Match(newRequest("here is a needle!")) {
		t.Error("expected match when needle is within max_size")
	}
}

func TestEquals_NoMatchOnTruncatedBody(t *testing.T) {
	m := &MatchBody{Equals: "short", MaxSize: 3}
	mustProvision(t, m)

	// Body is "short" (5 bytes), max_size is 3 — we read 3 bytes,
	// body is truncated, eq should not match on truncated content.
	if m.Match(newRequest("short")) {
		t.Error("eq should not match on truncated body")
	}
}

// --- Body re-wrapping for downstream ---

func TestBodyReWrapped(t *testing.T) {
	m := &MatchBody{Contains: "test"}
	mustProvision(t, m)

	r := newRequest("this is a test body")
	m.Match(r)

	// Downstream should still be able to read the full body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read re-wrapped body: %v", err)
	}
	if string(body) != "this is a test body" {
		t.Errorf("expected body to be preserved, got %q", string(body))
	}
}

func TestBodyReWrapped_LargerThanMaxSize(t *testing.T) {
	m := &MatchBody{Contains: "needle", MaxSize: 10}
	mustProvision(t, m)

	original := "0123456789abcdefghij"
	r := newRequest(original)
	m.Match(r)

	// Downstream should get the full body back
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read re-wrapped body: %v", err)
	}
	if string(body) != original {
		t.Errorf("expected full body preserved, got %q (len %d)", string(body), len(body))
	}
}

// --- JSON Matching ---

func TestJSON_EqMatch(t *testing.T) {
	m := &MatchBody{JSONPath: ".user.role", JSONOp: "eq", JSONValue: "admin"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"user":{"role":"admin","name":"bob"}}`)) {
		t.Error("expected JSON eq match")
	}
}

func TestJSON_EqNoMatch(t *testing.T) {
	m := &MatchBody{JSONPath: ".user.role", JSONOp: "eq", JSONValue: "admin"}
	mustProvision(t, m)

	if m.Match(newRequest(`{"user":{"role":"viewer","name":"bob"}}`)) {
		t.Error("expected no JSON eq match")
	}
}

func TestJSON_ContainsMatch(t *testing.T) {
	m := &MatchBody{JSONPath: ".message", JSONOp: "contains", JSONValue: "hello"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"message":"say hello world"}`)) {
		t.Error("expected JSON contains match")
	}
}

func TestJSON_RegexMatch(t *testing.T) {
	m := &MatchBody{JSONPath: ".email", JSONOp: "regex", JSONValue: `^[a-z]+@example\.com$`}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"email":"bob@example.com"}`)) {
		t.Error("expected JSON regex match")
	}
}

func TestJSON_RegexNoMatch(t *testing.T) {
	m := &MatchBody{JSONPath: ".email", JSONOp: "regex", JSONValue: `^[a-z]+@example\.com$`}
	mustProvision(t, m)

	if m.Match(newRequest(`{"email":"BOB@other.com"}`)) {
		t.Error("expected no JSON regex match")
	}
}

func TestJSON_Exists(t *testing.T) {
	m := &MatchBody{JSONPath: ".user.role", JSONOp: "exists"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"user":{"role":"admin"}}`)) {
		t.Error("expected JSON exists match")
	}
	if m.Match(newRequest(`{"user":{"name":"bob"}}`)) {
		t.Error("expected no JSON exists match when field missing")
	}
}

func TestJSON_NestedArray(t *testing.T) {
	m := &MatchBody{JSONPath: ".items.0.type", JSONOp: "eq", JSONValue: "widget"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"items":[{"type":"widget"},{"type":"gadget"}]}`)) {
		t.Error("expected JSON array index match")
	}
}

func TestJSON_NumericValue(t *testing.T) {
	m := &MatchBody{JSONPath: ".count", JSONOp: "eq", JSONValue: "42"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"count":42}`)) {
		t.Error("expected JSON numeric value match")
	}
}

func TestJSON_BoolValue(t *testing.T) {
	m := &MatchBody{JSONPath: ".active", JSONOp: "eq", JSONValue: "true"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"active":true}`)) {
		t.Error("expected JSON bool value match")
	}
}

func TestJSON_NullValue(t *testing.T) {
	m := &MatchBody{JSONPath: ".deleted_at", JSONOp: "eq", JSONValue: "null"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"deleted_at":null}`)) {
		t.Error("expected JSON null value match")
	}
}

func TestJSON_InvalidBody(t *testing.T) {
	m := &MatchBody{JSONPath: ".user", JSONOp: "exists"}
	mustProvision(t, m)

	if m.Match(newRequest("not json at all")) {
		t.Error("expected no match on invalid JSON body")
	}
}

func TestJSON_WithoutLeadingDot(t *testing.T) {
	m := &MatchBody{JSONPath: "user.role", JSONOp: "eq", JSONValue: "admin"}
	mustProvision(t, m)

	if !m.Match(newRequest(`{"user":{"role":"admin"}}`)) {
		t.Error("expected match even without leading dot in path")
	}
}

// --- Form Matching ---

func TestForm_EqMatch(t *testing.T) {
	m := &MatchBody{FormField: "username", FormOp: "eq", FormValue: "admin"}
	mustProvision(t, m)

	if !m.Match(newRequest("username=admin&password=secret")) {
		t.Error("expected form eq match")
	}
}

func TestForm_EqNoMatch(t *testing.T) {
	m := &MatchBody{FormField: "username", FormOp: "eq", FormValue: "admin"}
	mustProvision(t, m)

	if m.Match(newRequest("username=user&password=secret")) {
		t.Error("expected no form eq match")
	}
}

func TestForm_ContainsMatch(t *testing.T) {
	m := &MatchBody{FormField: "query", FormOp: "contains", FormValue: "SELECT"}
	mustProvision(t, m)

	if !m.Match(newRequest("query=SELECT+*+FROM+users&limit=10")) {
		t.Error("expected form contains match")
	}
}

func TestForm_RegexMatch(t *testing.T) {
	m := &MatchBody{FormField: "email", FormOp: "regex", FormValue: `@example\.com$`}
	mustProvision(t, m)

	if !m.Match(newRequest("email=bob%40example.com&name=Bob")) {
		t.Error("expected form regex match")
	}
}

func TestForm_MissingField(t *testing.T) {
	m := &MatchBody{FormField: "token", FormOp: "eq", FormValue: "abc"}
	mustProvision(t, m)

	if m.Match(newRequest("username=admin&password=secret")) {
		t.Error("expected no match when form field is missing")
	}
}

func TestForm_MultipleValues(t *testing.T) {
	m := &MatchBody{FormField: "tag", FormOp: "eq", FormValue: "important"}
	mustProvision(t, m)

	// tag appears twice; should match if any value matches
	if !m.Match(newRequest("tag=normal&tag=important&name=test")) {
		t.Error("expected form match on one of multiple values")
	}
}

func TestForm_InvalidBody(t *testing.T) {
	m := &MatchBody{FormField: "username", FormOp: "eq", FormValue: "admin"}
	mustProvision(t, m)

	// Sending JSON body for form parsing — ParseQuery is lenient so
	// it won't match "username" field from JSON
	if m.Match(newRequest(`{"username":"admin"}`)) {
		t.Error("expected no match when body is JSON, not form-encoded")
	}
}

// --- Validation ---

func TestValidate_NoMatchType(t *testing.T) {
	m := &MatchBody{}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for empty matcher")
	}
}

func TestValidate_MultipleMatchTypes(t *testing.T) {
	m := &MatchBody{Contains: "foo", Regex: "bar"}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for multiple match types")
	}
}

func TestValidate_JSONMissingOp(t *testing.T) {
	m := &MatchBody{JSONPath: ".user"}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for JSON without op")
	}
}

func TestValidate_JSONInvalidOp(t *testing.T) {
	m := &MatchBody{JSONPath: ".user", JSONOp: "nope"}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for invalid JSON op")
	}
}

func TestValidate_JSONMissingValue(t *testing.T) {
	m := &MatchBody{JSONPath: ".user", JSONOp: "eq"}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for JSON eq without value")
	}
}

func TestValidate_JSONExistsNoValue(t *testing.T) {
	m := &MatchBody{JSONPath: ".user", JSONOp: "exists"}
	err := m.Validate()
	if err != nil {
		t.Errorf("json_exists should not require a value: %v", err)
	}
}

func TestValidate_FormMissingOp(t *testing.T) {
	m := &MatchBody{FormField: "user"}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for form without op")
	}
}

func TestValidate_NegativeMaxSize(t *testing.T) {
	m := &MatchBody{Contains: "test", MaxSize: -1}
	err := m.Validate()
	if err == nil {
		t.Error("expected validation error for negative max_size")
	}
}

// --- parseSize ---

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		{"1024", 1024, false},
		{"1kb", 1024, false},
		{"1KB", 1024, false},
		{"13mb", 13 * 1024 * 1024, false},
		{"13MB", 13 * 1024 * 1024, false},
		{"1gb", 1024 * 1024 * 1024, false},
		{"100b", 100, false},
		{"abc", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSize(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
				return
			}
			if got != tt.expected {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

// --- resolveJSONPath ---

func TestResolveJSONPath(t *testing.T) {
	body := []byte(`{
		"user": {"role": "admin", "tags": ["a", "b"]},
		"count": 42,
		"active": true,
		"items": [{"type": "widget"}, {"type": "gadget"}]
	}`)

	tests := []struct {
		path    string
		wantVal string
		wantOK  bool
	}{
		{".user.role", "admin", true},
		{"user.role", "admin", true},
		{".count", "42", true},
		{".active", "true", true},
		{".items.0.type", "widget", true},
		{".items.1.type", "gadget", true},
		{".items.2.type", "", false},
		{".missing", "", false},
		{".user.missing", "", false},
		{".", "", true}, // root — returns the whole object
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			val, ok := resolveJSONPath(body, tt.path)
			if ok != tt.wantOK {
				t.Errorf("resolveJSONPath(%q): ok = %v, want %v", tt.path, ok, tt.wantOK)
				return
			}
			if ok && tt.path != "." {
				str := jsonValueToString(val)
				if str != tt.wantVal {
					t.Errorf("resolveJSONPath(%q) = %q, want %q", tt.path, str, tt.wantVal)
				}
			}
		})
	}
}

// --- jsonValueToString ---

func TestJsonValueToString(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want string
	}{
		{"string", "hello", "hello"},
		{"int float", float64(42), "42"},
		{"float", float64(3.14), "3.14"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"nil", nil, "null"},
		{"array", []interface{}{"a", "b"}, `["a","b"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonValueToString(tt.val)
			if got != tt.want {
				t.Errorf("jsonValueToString(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}

// ─── BodyVars Handler Tests ─────────────────────────────────────────

// newVarsRequest creates an HTTP request with Caddy's variable table
// initialized in the context, enabling SetVar/GetVar.
func newVarsRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	vars := make(map[string]any)
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars)
	return r.WithContext(ctx)
}

// noopHandler is a caddyhttp.Handler that does nothing (returns nil).
type noopHandler struct{}

func (noopHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func mustProvisionBodyVars(t *testing.T, bv *BodyVars) {
	t.Helper()
	if bv.MaxSize == 0 {
		bv.MaxSize = defaultMaxSize
	}
	ctx, cancel := testContext()
	defer cancel()
	if err := bv.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
}

// --- BodyVars: JSON extraction ---

func TestBodyVars_JSONSingleField(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user.api_key"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"user":{"api_key":"sk-12345","name":"bob"}}`)
	w := httptest.NewRecorder()
	err := bv.ServeHTTP(w, r, noopHandler{})
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	got := caddyhttp.GetVar(r.Context(), "body_json.user.api_key")
	if got != "sk-12345" {
		t.Errorf("expected body_json.user.api_key = %q, got %v", "sk-12345", got)
	}
}

func TestBodyVars_JSONMultipleFields(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user.role", ".tenant.id"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"user":{"role":"admin"},"tenant":{"id":"t-999"}}`)
	w := httptest.NewRecorder()
	err := bv.ServeHTTP(w, r, noopHandler{})
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	role := caddyhttp.GetVar(r.Context(), "body_json.user.role")
	if role != "admin" {
		t.Errorf("expected body_json.user.role = %q, got %v", "admin", role)
	}
	tid := caddyhttp.GetVar(r.Context(), "body_json.tenant.id")
	if tid != "t-999" {
		t.Errorf("expected body_json.tenant.id = %q, got %v", "t-999", tid)
	}
}

func TestBodyVars_JSONNestedArray(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".items.0.type"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"items":[{"type":"widget"},{"type":"gadget"}]}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_json.items.0.type")
	if got != "widget" {
		t.Errorf("expected body_json.items.0.type = %q, got %v", "widget", got)
	}
}

func TestBodyVars_JSONNumericValue(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".count"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"count":42}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_json.count")
	if got != "42" {
		t.Errorf("expected body_json.count = %q, got %v", "42", got)
	}
}

func TestBodyVars_JSONBoolValue(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".active"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"active":true}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_json.active")
	if got != "true" {
		t.Errorf("expected body_json.active = %q, got %v", "true", got)
	}
}

func TestBodyVars_JSONMissingField(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user.missing"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"user":{"name":"bob"}}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_json.user.missing")
	if got != nil {
		t.Errorf("expected nil for missing field, got %v", got)
	}
}

func TestBodyVars_JSONInvalidBody(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("not json at all")
	w := httptest.NewRecorder()
	err := bv.ServeHTTP(w, r, noopHandler{})
	if err != nil {
		t.Fatalf("should not error on invalid JSON, just skip: %v", err)
	}

	got := caddyhttp.GetVar(r.Context(), "body_json.user")
	if got != nil {
		t.Errorf("expected nil for invalid JSON body, got %v", got)
	}
}

func TestBodyVars_JSONWithoutLeadingDot(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{"user.role"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest(`{"user":{"role":"admin"}}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	// Variable name should still be body_json.user.role (no leading dot)
	got := caddyhttp.GetVar(r.Context(), "body_json.user.role")
	if got != "admin" {
		t.Errorf("expected body_json.user.role = %q, got %v", "admin", got)
	}
}

// --- BodyVars: Form extraction ---

func TestBodyVars_FormSingleField(t *testing.T) {
	bv := &BodyVars{FormFields: []string{"action"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("action=deploy&target=prod")
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_form.action")
	if got != "deploy" {
		t.Errorf("expected body_form.action = %q, got %v", "deploy", got)
	}
}

func TestBodyVars_FormMultipleFields(t *testing.T) {
	bv := &BodyVars{FormFields: []string{"action", "token"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("action=deploy&token=abc123&extra=ignored")
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	action := caddyhttp.GetVar(r.Context(), "body_form.action")
	if action != "deploy" {
		t.Errorf("expected body_form.action = %q, got %v", "deploy", action)
	}
	token := caddyhttp.GetVar(r.Context(), "body_form.token")
	if token != "abc123" {
		t.Errorf("expected body_form.token = %q, got %v", "abc123", token)
	}
}

func TestBodyVars_FormMultiValue_UsesFirst(t *testing.T) {
	bv := &BodyVars{FormFields: []string{"tag"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("tag=first&tag=second")
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_form.tag")
	if got != "first" {
		t.Errorf("expected body_form.tag = %q (first value), got %v", "first", got)
	}
}

func TestBodyVars_FormMissingField(t *testing.T) {
	bv := &BodyVars{FormFields: []string{"missing"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("action=deploy&target=prod")
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_form.missing")
	if got != nil {
		t.Errorf("expected nil for missing form field, got %v", got)
	}
}

func TestBodyVars_FormURLEncoded(t *testing.T) {
	bv := &BodyVars{FormFields: []string{"email"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("email=bob%40example.com&name=Bob")
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	got := caddyhttp.GetVar(r.Context(), "body_form.email")
	if got != "bob@example.com" {
		t.Errorf("expected body_form.email = %q, got %v", "bob@example.com", got)
	}
}

// --- BodyVars: Mixed JSON + Form ---

func TestBodyVars_MixedJSONAndForm(t *testing.T) {
	// When both JSON and Form are configured, JSON parse may fail on
	// form data (and vice versa), but neither should error — just skip.
	bv := &BodyVars{
		JSONPaths:  []string{".user.role"},
		FormFields: []string{"action"},
	}
	mustProvisionBodyVars(t, bv)

	// JSON body — JSON should match, form should not
	r := newVarsRequest(`{"user":{"role":"admin"}}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	role := caddyhttp.GetVar(r.Context(), "body_json.user.role")
	if role != "admin" {
		t.Errorf("expected body_json.user.role = %q, got %v", "admin", role)
	}
	action := caddyhttp.GetVar(r.Context(), "body_form.action")
	if action != nil {
		t.Errorf("expected nil for form field on JSON body, got %v", action)
	}
}

// --- BodyVars: Body re-wrapping ---

func TestBodyVars_BodyPreservedForDownstream(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user.role"}}
	mustProvisionBodyVars(t, bv)

	original := `{"user":{"role":"admin","name":"bob"}}`
	r := newVarsRequest(original)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	// Downstream should still be able to read the full body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read re-wrapped body: %v", err)
	}
	if string(body) != original {
		t.Errorf("expected body to be preserved, got %q", string(body))
	}
}

func TestBodyVars_NilBody(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}}
	mustProvisionBodyVars(t, bv)

	r := httptest.NewRequest("GET", "/", nil)
	vars := make(map[string]any)
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	err := bv.ServeHTTP(w, r, noopHandler{})
	if err != nil {
		t.Fatalf("should not error on nil body: %v", err)
	}
}

func TestBodyVars_EmptyBody(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}}
	mustProvisionBodyVars(t, bv)

	r := newVarsRequest("")
	w := httptest.NewRecorder()
	err := bv.ServeHTTP(w, r, noopHandler{})
	if err != nil {
		t.Fatalf("should not error on empty body: %v", err)
	}

	got := caddyhttp.GetVar(r.Context(), "body_json.user")
	if got != nil {
		t.Errorf("expected nil for empty body, got %v", got)
	}
}

// --- BodyVars: next handler called ---

func TestBodyVars_NextHandlerCalled(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}}
	mustProvisionBodyVars(t, bv)

	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})

	r := newVarsRequest(`{"user":"test"}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, next)

	if !called {
		t.Error("next handler was not called")
	}
}

func TestBodyVars_NextHandlerCalledOnNilBody(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}}
	mustProvisionBodyVars(t, bv)

	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})

	r := httptest.NewRequest("GET", "/", nil)
	vars := make(map[string]any)
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, next)

	if !called {
		t.Error("next handler was not called on nil body")
	}
}

// --- BodyVars: Validation ---

func TestBodyVars_Validate_NoFields(t *testing.T) {
	bv := &BodyVars{}
	err := bv.Validate()
	if err == nil {
		t.Error("expected validation error for empty body_vars")
	}
}

func TestBodyVars_Validate_NegativeMaxSize(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}, MaxSize: -1}
	err := bv.Validate()
	if err == nil {
		t.Error("expected validation error for negative max_size")
	}
}

func TestBodyVars_Validate_JSONOnly(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}}
	err := bv.Validate()
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestBodyVars_Validate_FormOnly(t *testing.T) {
	bv := &BodyVars{FormFields: []string{"action"}}
	err := bv.Validate()
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestBodyVars_Validate_Mixed(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".user"}, FormFields: []string{"action"}}
	err := bv.Validate()
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

// --- BodyVars: MaxSize ---

func TestBodyVars_MaxSizeRespectsLimit(t *testing.T) {
	bv := &BodyVars{JSONPaths: []string{".key"}, MaxSize: 10}
	mustProvisionBodyVars(t, bv)

	// Body is 19 bytes, beyond max_size of 10 — JSON parse will fail on truncated body
	r := newVarsRequest(`{"key":"longvalue"}`)
	w := httptest.NewRecorder()
	bv.ServeHTTP(w, r, noopHandler{})

	// Should not have set the variable since JSON is truncated/invalid
	got := caddyhttp.GetVar(r.Context(), "body_json.key")
	if got != nil {
		t.Errorf("expected nil for truncated body, got %v", got)
	}

	// But body should still be preserved for downstream
	body, _ := io.ReadAll(r.Body)
	if len(body) < 19 {
		t.Errorf("expected full body preserved, got %d bytes", len(body))
	}
}

// --- BodyVars: CaddyModule info ---

func TestBodyVars_CaddyModule(t *testing.T) {
	bv := BodyVars{}
	info := bv.CaddyModule()
	if info.ID != "http.handlers.body_vars" {
		t.Errorf("expected module ID %q, got %q", "http.handlers.body_vars", info.ID)
	}
	if info.New == nil {
		t.Error("expected non-nil New function")
	}
}
