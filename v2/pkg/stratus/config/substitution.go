package config

import "regexp"

// templateVarPattern matches %%name%% where name is lowercase letters and underscores.
// The chosen syntax aligns with Datadog Agent's tag autodiscovery template variables
// (e.g. %%kube_namespace%%).
var templateVarPattern = regexp.MustCompile(`%%([a-z_]+)%%`)

// SubstitutionVars holds the values Stratus substitutes into config string values.
// Unknown names — and names whose value is empty — are left untouched (passed
// through verbatim). Treating empty values as unknown prevents missing context
// from silently collapsing %%correlation_id%% into "" downstream, which would
// risk resource-name collisions across detonations.
type SubstitutionVars struct {
	CorrelationID string
}

// varNameCorrelationID is the whitelisted name accepted in %%...%% markers for
// the correlation ID. Kept as a constant so the whitelist string lives in exactly
// one place alongside the SubstitutionVars field it resolves from.
const varNameCorrelationID = "correlation_id"

// lookup returns the substitution for a named variable and whether it should be
// applied. See SubstitutionVars for the empty-value semantics.
func (v SubstitutionVars) lookup(name string) (string, bool) {
	switch name {
	case varNameCorrelationID:
		if v.CorrelationID == "" {
			return "", false
		}
		return v.CorrelationID, true
	default:
		return "", false
	}
}

// substitute replaces %%name%% occurrences whose name is in the whitelist; other
// occurrences are returned verbatim.
func (v SubstitutionVars) substitute(s string) string {
	return templateVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		// FindStringSubmatch keeps the name extraction tied to the regex; if the
		// pattern is widened or its delimiters change, this code keeps working.
		sub := templateVarPattern.FindStringSubmatch(match)
		if value, ok := v.lookup(sub[1]); ok {
			return value
		}
		return match
	})
}

// substituteMap returns a new map with the same shape as m and all string leaves
// substituted via vars. The caller's map is not mutated.
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
