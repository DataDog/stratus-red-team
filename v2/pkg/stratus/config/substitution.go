package config

import (
	"bytes"
	"log"
	"text/template"
)

// SubstitutionVars holds values substituted into config string values. Users
// reference each variable in YAML via Go's text/template syntax with <% %>
// delimiters — e.g. <%.CorrelationID%>. Adding a new variable: add a field
// below and have callers populate it; users reference it by the exported field
// name.
//
// The non-default <% %> delimiters were chosen to avoid (a) YAML parsers
// interpreting [[ ]] as nested flow sequences, and (b) some editors (VSCode,
// Cursor) splitting the default {{ }} markers into "{ {" on save.
type SubstitutionVars struct {
	CorrelationID string
}

// substitute returns s with template expressions resolved from v. Parse or
// execute errors (malformed delimiters, unknown field references) leave s
// unchanged and log the cause so typos surface as literal <% %> markers in
// the output rather than aborting warmup.
func (v SubstitutionVars) substitute(s string) string {
	tmpl, err := template.New("").Delims("<%", "%>").Parse(s)
	if err != nil {
		log.Printf("config substitution: parse %q: %v", s, err)
		return s
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		log.Printf("config substitution: execute %q: %v", s, err)
		return s
	}
	return buf.String()
}

// substituteMap returns a new map with the same shape as m and all string
// leaves substituted via vars. The caller's map is not mutated.
func substituteMap(m map[string]any, vars SubstitutionVars) map[string]any {
	result := make(map[string]any, len(m))
	for k, val := range m {
		result[k] = substituteValue(val, vars)
	}
	return result
}

// substituteValue walks a parsed-YAML value tree and applies substitution to
// every string leaf. Map keys are intentionally not substituted. The walker
// handles the shapes Viper produces (string, map[string]any, []any); other Go
// types are passed through unchanged.
func substituteValue(v any, vars SubstitutionVars) any {
	switch x := v.(type) {
	case string:
		return vars.substitute(x)
	case map[string]any:
		return substituteMap(x, vars)
	case []any:
		result := make([]any, len(x))
		for i, item := range x {
			result[i] = substituteValue(item, vars)
		}
		return result
	default:
		return v
	}
}
