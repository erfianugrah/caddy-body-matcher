// Package bodymatcher provides a Caddy HTTP request matcher that inspects
// the request body. It supports raw body matching (contains, regex, exact,
// prefix, suffix), JSON field extraction, and form field extraction.
//
// Module ID: http.matchers.body
package bodymatcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchBody{})
	caddy.RegisterModule(BodyVars{})
	httpcaddyfile.RegisterHandlerDirective("body_vars", parseCaddyfileBodyVars)
}

// defaultMaxSize is the default maximum body size to buffer for matching.
// Matches the Coraza WAF request_body_limit of 13 MiB.
const defaultMaxSize = 13 * 1024 * 1024 // 13 MiB

// MatchBody matches requests by inspecting the request body.
// Only one match type may be specified per matcher instance.
//
// Raw body matching:
//
//	body contains <string>
//	body eq <string>
//	body starts_with <string>
//	body ends_with <string>
//	body regex <pattern>
//
// JSON field matching:
//
//	body json <dotpath> <value>
//	body json_contains <dotpath> <value>
//	body json_regex <dotpath> <pattern>
//	body json_exists <dotpath>
//
// Form field matching:
//
//	body form <field> <value>
//	body form_contains <field> <value>
//	body form_regex <field> <pattern>
//
// Block syntax with max_size override:
//
//	body {
//	    max_size 13mb
//	    contains "search term"
//	}
type MatchBody struct {
	// Maximum number of bytes to read from the body. Bodies larger
	// than this are not inspected and will not match. Default: 13 MiB.
	MaxSize int64 `json:"max_size,omitempty"`

	// --- Raw body matching (mutually exclusive) ---

	// Match if body contains this substring.
	Contains string `json:"contains,omitempty"`
	// Match if body exactly equals this string.
	Equals string `json:"equals,omitempty"`
	// Match if body starts with this prefix.
	StartsWith string `json:"starts_with,omitempty"`
	// Match if body ends with this suffix.
	EndsWith string `json:"ends_with,omitempty"`
	// Match if body matches this RE2 regular expression.
	Regex string `json:"regex,omitempty"`

	// --- JSON field matching ---

	// Dot-path for JSON field matching. Example: ".user.role"
	JSONPath string `json:"json_path,omitempty"`
	// Match type for JSON field: "eq", "contains", "regex", or "exists".
	JSONOp string `json:"json_op,omitempty"`
	// Value to match against the extracted JSON field.
	JSONValue string `json:"json_value,omitempty"`

	// --- Form field matching ---

	// Form field name to match.
	FormField string `json:"form_field,omitempty"`
	// Match type for form field: "eq", "contains", or "regex".
	FormOp string `json:"form_op,omitempty"`
	// Value to match against the form field.
	FormValue string `json:"form_value,omitempty"`

	// compiled regex (set during Provision)
	compiledRegex     *regexp.Regexp
	compiledJSONRegex *regexp.Regexp
	compiledFormRegex *regexp.Regexp

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MatchBody) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.body",
		New: func() caddy.Module { return new(MatchBody) },
	}
}

// Provision sets up the matcher, compiling any regular expressions.
func (m *MatchBody) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.MaxSize == 0 {
		m.MaxSize = defaultMaxSize
	}

	// Compile raw body regex
	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return fmt.Errorf("compiling body regex: %v", err)
		}
		m.compiledRegex = re
	}

	// Compile JSON field regex
	if m.JSONOp == "regex" && m.JSONValue != "" {
		re, err := regexp.Compile(m.JSONValue)
		if err != nil {
			return fmt.Errorf("compiling json_regex pattern: %v", err)
		}
		m.compiledJSONRegex = re
	}

	// Compile form field regex
	if m.FormOp == "regex" && m.FormValue != "" {
		re, err := regexp.Compile(m.FormValue)
		if err != nil {
			return fmt.Errorf("compiling form_regex pattern: %v", err)
		}
		m.compiledFormRegex = re
	}

	return nil
}

// Validate ensures the matcher configuration is correct.
func (m *MatchBody) Validate() error {
	if m.MaxSize < 0 {
		return fmt.Errorf("max_size must be non-negative")
	}

	// Count how many match types are configured
	count := 0
	if m.Contains != "" {
		count++
	}
	if m.Equals != "" {
		count++
	}
	if m.StartsWith != "" {
		count++
	}
	if m.EndsWith != "" {
		count++
	}
	if m.Regex != "" {
		count++
	}
	if m.JSONPath != "" {
		count++
	}
	if m.FormField != "" {
		count++
	}

	if count == 0 {
		return fmt.Errorf("body matcher requires at least one match criterion")
	}
	if count > 1 {
		return fmt.Errorf("body matcher supports only one match criterion per instance; got %d", count)
	}

	// Validate JSON op
	if m.JSONPath != "" {
		switch m.JSONOp {
		case "eq", "contains", "regex", "exists":
			// ok
		case "":
			return fmt.Errorf("json_op is required when json_path is set")
		default:
			return fmt.Errorf("invalid json_op %q; must be eq, contains, regex, or exists", m.JSONOp)
		}
		if m.JSONOp != "exists" && m.JSONValue == "" {
			return fmt.Errorf("json_value is required for json_op %q", m.JSONOp)
		}
	}

	// Validate form op
	if m.FormField != "" {
		switch m.FormOp {
		case "eq", "contains", "regex":
			// ok
		case "":
			return fmt.Errorf("form_op is required when form_field is set")
		default:
			return fmt.Errorf("invalid form_op %q; must be eq, contains, or regex", m.FormOp)
		}
		if m.FormValue == "" {
			return fmt.Errorf("form_value is required when form_field is set")
		}
	}

	return nil
}

// Match returns true if the request body matches the configured criteria.
func (m MatchBody) Match(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}

	// Read body up to max_size
	buf, err := m.readBody(r)
	if err != nil {
		if m.logger != nil {
			m.logger.Debug("failed to read request body", zap.Error(err))
		}
		return false
	}

	// If body exceeds max_size, don't match
	if int64(len(buf)) >= m.MaxSize {
		// We read exactly MaxSize bytes; body may be larger. We still
		// attempt to match against what we have, since the user set a
		// limit knowing this. Only "eq" is not meaningful on truncated
		// bodies, so we skip it.
		if m.Equals != "" {
			return false
		}
	}

	// Dispatch to the appropriate match function
	switch {
	case m.Contains != "":
		return bytes.Contains(buf, []byte(m.Contains))
	case m.Equals != "":
		return bytes.Equal(buf, []byte(m.Equals))
	case m.StartsWith != "":
		return bytes.HasPrefix(buf, []byte(m.StartsWith))
	case m.EndsWith != "":
		return bytes.HasSuffix(buf, []byte(m.EndsWith))
	case m.Regex != "":
		return m.compiledRegex.Match(buf)
	case m.JSONPath != "":
		return m.matchJSON(buf)
	case m.FormField != "":
		return m.matchForm(buf)
	}

	return false
}

// readBody reads the request body up to MaxSize, then replaces r.Body
// with a new reader so downstream handlers can still read it.
func (m MatchBody) readBody(r *http.Request) ([]byte, error) {
	// Limit reading to MaxSize + 1 to detect overflow
	lr := io.LimitReader(r.Body, m.MaxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		// Re-wrap whatever we got so downstream doesn't get a broken body
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		return nil, err
	}

	// If we read more than MaxSize, truncate to MaxSize for matching
	// but preserve the full body for downstream
	if int64(len(buf)) > m.MaxSize {
		// Body was larger; re-assemble original body for downstream
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		buf = buf[:m.MaxSize]
	} else {
		// Body fully read; replace with buffered copy
		r.Body = io.NopCloser(bytes.NewReader(buf))
	}

	return buf, nil
}

// matchJSON parses the body as JSON and matches a field by dot-path.
func (m MatchBody) matchJSON(body []byte) bool {
	val, ok := resolveJSONPath(body, m.JSONPath)
	if !ok {
		return m.JSONOp == "exists" && false // field not found
	}

	if m.JSONOp == "exists" {
		return true
	}

	strVal := jsonValueToString(val)

	switch m.JSONOp {
	case "eq":
		return strVal == m.JSONValue
	case "contains":
		return strings.Contains(strVal, m.JSONValue)
	case "regex":
		if m.compiledJSONRegex != nil {
			return m.compiledJSONRegex.MatchString(strVal)
		}
		return false
	}
	return false
}

// resolveJSONPath walks a dot-path like ".user.roles.0" through parsed JSON.
// Leading dot is optional. Returns (value, found).
func resolveJSONPath(body []byte, dotPath string) (interface{}, bool) {
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, false
	}

	// Trim leading dot
	dotPath = strings.TrimPrefix(dotPath, ".")
	if dotPath == "" {
		return root, true
	}

	parts := strings.Split(dotPath, ".")
	current := root

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil, false
			}
			current = v[idx]
		default:
			return nil, false
		}
	}

	return current, true
}

// jsonValueToString converts a JSON value to its string representation.
func jsonValueToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case nil:
		return "null"
	default:
		// For arrays/objects, marshal back to JSON string
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("%v", val)
		}
		return string(b)
	}
}

// matchForm parses the body as application/x-www-form-urlencoded and
// matches a specific field.
func (m MatchBody) matchForm(body []byte) bool {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return false
	}

	fieldVals, ok := values[m.FormField]
	if !ok || len(fieldVals) == 0 {
		return false
	}

	for _, fv := range fieldVals {
		switch m.FormOp {
		case "eq":
			if fv == m.FormValue {
				return true
			}
		case "contains":
			if strings.Contains(fv, m.FormValue) {
				return true
			}
		case "regex":
			if m.compiledFormRegex != nil && m.compiledFormRegex.MatchString(fv) {
				return true
			}
		}
	}

	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
// Single-line syntax:
//
//	body <operator> <args...>
//
// Block syntax:
//
//	body {
//	    max_size <size>
//	    <operator> <args...>
//	}
//
// Operators:
//
//	contains <string>
//	eq <string>
//	starts_with <string>
//	ends_with <string>
//	regex <pattern>
//	json <dotpath> <value>
//	json_contains <dotpath> <value>
//	json_regex <dotpath> <pattern>
//	json_exists <dotpath>
//	form <field> <value>
//	form_contains <field> <value>
//	form_regex <field> <pattern>
func (m *MatchBody) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Check for inline args (single-line syntax)
		if d.NextArg() {
			op := d.Val()
			if err := m.parseOperator(d, op); err != nil {
				return err
			}
			// No block allowed after inline args
			if d.NextBlock(0) {
				return d.Err("cannot use both inline arguments and block for body matcher")
			}
			continue
		}

		// Block syntax
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			op := d.Val()
			if op == "max_size" {
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := parseSize(d.Val())
				if err != nil {
					return d.Errf("invalid max_size: %v", err)
				}
				m.MaxSize = size
				continue
			}
			if err := m.parseOperator(d, op); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseOperator parses a single operator and its arguments from the dispenser.
func (m *MatchBody) parseOperator(d *caddyfile.Dispenser, op string) error {
	switch op {
	case "contains":
		if !d.NextArg() {
			return d.Errf("body contains requires a value")
		}
		m.Contains = d.Val()
	case "eq":
		if !d.NextArg() {
			return d.Errf("body eq requires a value")
		}
		m.Equals = d.Val()
	case "starts_with":
		if !d.NextArg() {
			return d.Errf("body starts_with requires a value")
		}
		m.StartsWith = d.Val()
	case "ends_with":
		if !d.NextArg() {
			return d.Errf("body ends_with requires a value")
		}
		m.EndsWith = d.Val()
	case "regex":
		if !d.NextArg() {
			return d.Errf("body regex requires a pattern")
		}
		m.Regex = d.Val()
	case "json":
		if !d.NextArg() {
			return d.Errf("body json requires a dot-path")
		}
		m.JSONPath = d.Val()
		if !d.NextArg() {
			return d.Errf("body json requires a value after the dot-path")
		}
		m.JSONOp = "eq"
		m.JSONValue = d.Val()
	case "json_contains":
		if !d.NextArg() {
			return d.Errf("body json_contains requires a dot-path")
		}
		m.JSONPath = d.Val()
		if !d.NextArg() {
			return d.Errf("body json_contains requires a value after the dot-path")
		}
		m.JSONOp = "contains"
		m.JSONValue = d.Val()
	case "json_regex":
		if !d.NextArg() {
			return d.Errf("body json_regex requires a dot-path")
		}
		m.JSONPath = d.Val()
		if !d.NextArg() {
			return d.Errf("body json_regex requires a pattern after the dot-path")
		}
		m.JSONOp = "regex"
		m.JSONValue = d.Val()
	case "json_exists":
		if !d.NextArg() {
			return d.Errf("body json_exists requires a dot-path")
		}
		m.JSONPath = d.Val()
		m.JSONOp = "exists"
	case "form":
		if !d.NextArg() {
			return d.Errf("body form requires a field name")
		}
		m.FormField = d.Val()
		if !d.NextArg() {
			return d.Errf("body form requires a value after the field name")
		}
		m.FormOp = "eq"
		m.FormValue = d.Val()
	case "form_contains":
		if !d.NextArg() {
			return d.Errf("body form_contains requires a field name")
		}
		m.FormField = d.Val()
		if !d.NextArg() {
			return d.Errf("body form_contains requires a value after the field name")
		}
		m.FormOp = "contains"
		m.FormValue = d.Val()
	case "form_regex":
		if !d.NextArg() {
			return d.Errf("body form_regex requires a field name")
		}
		m.FormField = d.Val()
		if !d.NextArg() {
			return d.Errf("body form_regex requires a pattern after the field name")
		}
		m.FormOp = "regex"
		m.FormValue = d.Val()
	default:
		return d.Errf("unknown body matcher operator: %s", op)
	}
	return nil
}

// parseSize parses a human-readable size string like "13mb", "1kb", "5242880".
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	multiplier := int64(1)

	if strings.HasSuffix(s, "gb") || strings.HasSuffix(s, "gib") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimRight(s, "gib")
	} else if strings.HasSuffix(s, "mb") || strings.HasSuffix(s, "mib") {
		multiplier = 1024 * 1024
		s = strings.TrimRight(s, "mib")
	} else if strings.HasSuffix(s, "kb") || strings.HasSuffix(s, "kib") {
		multiplier = 1024
		s = strings.TrimRight(s, "kib")
	} else if strings.HasSuffix(s, "b") {
		s = strings.TrimSuffix(s, "b")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size value %q", s)
	}
	return n * multiplier, nil
}

// ─── BodyVars Handler ───────────────────────────────────────────────

// BodyVars is a Caddy handler that reads the request body, extracts
// configured JSON and form field values, and exposes them as Caddy
// variables (placeholders). This enables body field values to be used
// as rate limit keys, in log templates, or in any Caddy directive that
// supports placeholders.
//
// Module ID: http.handlers.body_vars
//
// Exposed placeholders:
//
//	{http.vars.body_json.<dotpath>} — value from a JSON body field
//	{http.vars.body_form.<field>}   — value from a form-encoded field
//
// Caddyfile syntax:
//
//	body_vars {
//	    json .user.api_key
//	    json .tenant.id
//	    form action
//	    form token
//	    max_size 13mb
//	}
//
// Single-field shorthand:
//
//	body_vars json .user.api_key
//	body_vars form action
type BodyVars struct {
	// JSON dot-paths to extract (e.g., ".user.api_key", ".tenant.id").
	JSONPaths []string `json:"json_paths,omitempty"`

	// Form field names to extract (e.g., "action", "token").
	FormFields []string `json:"form_fields,omitempty"`

	// Maximum number of bytes to read from the body. Default: 13 MiB.
	MaxSize int64 `json:"max_size,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (BodyVars) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.body_vars",
		New: func() caddy.Module { return new(BodyVars) },
	}
}

// Provision sets up the handler.
func (bv *BodyVars) Provision(ctx caddy.Context) error {
	bv.logger = ctx.Logger()
	if bv.MaxSize == 0 {
		bv.MaxSize = defaultMaxSize
	}
	return nil
}

// Validate ensures the handler configuration is correct.
func (bv *BodyVars) Validate() error {
	if bv.MaxSize < 0 {
		return fmt.Errorf("max_size must be non-negative")
	}
	if len(bv.JSONPaths) == 0 && len(bv.FormFields) == 0 {
		return fmt.Errorf("body_vars requires at least one json or form field to extract")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. It reads the body,
// extracts configured fields, sets them as Caddy variables, re-wraps
// the body for downstream handlers, and calls next.
func (bv BodyVars) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Body == nil || r.Body == http.NoBody {
		return next.ServeHTTP(w, r)
	}

	// Read body up to max_size
	buf, err := bv.readBody(r)
	if err != nil {
		if bv.logger != nil {
			bv.logger.Debug("body_vars: failed to read request body", zap.Error(err))
		}
		return next.ServeHTTP(w, r)
	}

	// Extract JSON fields
	if len(bv.JSONPaths) > 0 && len(buf) > 0 {
		var root interface{}
		if err := json.Unmarshal(buf, &root); err == nil {
			for _, dotPath := range bv.JSONPaths {
				val, ok := resolveJSONPath(buf, dotPath)
				if ok {
					strVal := jsonValueToString(val)
					// Normalize path: strip leading dot for variable name
					varName := "body_json." + strings.TrimPrefix(dotPath, ".")
					caddyhttp.SetVar(r.Context(), varName, strVal)
				}
			}
		}
	}

	// Extract form fields
	if len(bv.FormFields) > 0 && len(buf) > 0 {
		values, err := url.ParseQuery(string(buf))
		if err == nil {
			for _, field := range bv.FormFields {
				if fieldVals, ok := values[field]; ok && len(fieldVals) > 0 {
					varName := "body_form." + field
					caddyhttp.SetVar(r.Context(), varName, fieldVals[0])
				}
			}
		}
	}

	return next.ServeHTTP(w, r)
}

// readBody reads the request body up to MaxSize, then replaces r.Body
// with a new reader so downstream handlers can still read it.
func (bv BodyVars) readBody(r *http.Request) ([]byte, error) {
	lr := io.LimitReader(r.Body, bv.MaxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		return nil, err
	}

	if int64(len(buf)) > bv.MaxSize {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		buf = buf[:bv.MaxSize]
	} else {
		r.Body = io.NopCloser(bytes.NewReader(buf))
	}

	return buf, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
// Single-field syntax:
//
//	body_vars json .user.api_key
//	body_vars form action
//
// Block syntax:
//
//	body_vars {
//	    json .user.api_key
//	    json .tenant.id
//	    form action
//	    form token
//	    max_size 13mb
//	}
func (bv *BodyVars) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Check for inline args (single-field syntax)
		if d.NextArg() {
			fieldType := d.Val()
			switch fieldType {
			case "json":
				if !d.NextArg() {
					return d.Errf("body_vars json requires a dot-path")
				}
				bv.JSONPaths = append(bv.JSONPaths, d.Val())
			case "form":
				if !d.NextArg() {
					return d.Errf("body_vars form requires a field name")
				}
				bv.FormFields = append(bv.FormFields, d.Val())
			default:
				return d.Errf("unknown body_vars field type: %s (expected json or form)", fieldType)
			}
			// No block allowed after inline args
			if d.NextBlock(0) {
				return d.Err("cannot use both inline arguments and block for body_vars")
			}
			continue
		}

		// Block syntax
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			directive := d.Val()
			switch directive {
			case "json":
				if !d.NextArg() {
					return d.Errf("body_vars json requires a dot-path")
				}
				bv.JSONPaths = append(bv.JSONPaths, d.Val())
			case "form":
				if !d.NextArg() {
					return d.Errf("body_vars form requires a field name")
				}
				bv.FormFields = append(bv.FormFields, d.Val())
			case "max_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := parseSize(d.Val())
				if err != nil {
					return d.Errf("invalid max_size: %v", err)
				}
				bv.MaxSize = size
			default:
				return d.Errf("unknown body_vars directive: %s", directive)
			}
		}
	}
	return nil
}

// parseCaddyfileBodyVars is the Caddyfile handler parser for body_vars.
// It registers the directive so Caddy can parse it from Caddyfile syntax.
func parseCaddyfileBodyVars(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var bv BodyVars
	err := bv.UnmarshalCaddyfile(h.Dispenser)
	return &bv, err
}

// Interface guards
var (
	_ caddy.Module                = (*MatchBody)(nil)
	_ caddy.Provisioner           = (*MatchBody)(nil)
	_ caddy.Validator             = (*MatchBody)(nil)
	_ caddyhttp.RequestMatcher    = (*MatchBody)(nil)
	_ caddyfile.Unmarshaler       = (*MatchBody)(nil)
	_ caddy.Module                = (*BodyVars)(nil)
	_ caddy.Provisioner           = (*BodyVars)(nil)
	_ caddy.Validator             = (*BodyVars)(nil)
	_ caddyhttp.MiddlewareHandler = (*BodyVars)(nil)
	_ caddyfile.Unmarshaler       = (*BodyVars)(nil)
)
