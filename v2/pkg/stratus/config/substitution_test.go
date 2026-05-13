package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testCorrelationID = "11111111-2222-3333-4444-555555555555"

func TestSubstitutionVars_substitute(t *testing.T) {
	tests := []struct {
		name     string
		vars     SubstitutionVars
		input    string
		expected string
	}{
		{
			name:     "no template markers",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "plain string",
			expected: "plain string",
		},
		{
			name:     "known variable",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "id=%%correlation_id%%",
			expected: "id=" + testCorrelationID,
		},
		{
			name:     "unknown variable passes through (e.g. DD Agent autodiscovery)",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    `{"ns":"%%kube_namespace%%"}`,
			expected: `{"ns":"%%kube_namespace%%"}`,
		},
		{
			name:     "known and unknown coexist",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    `{"id":"%%correlation_id%%","ns":"%%kube_namespace%%"}`,
			expected: `{"id":"` + testCorrelationID + `","ns":"%%kube_namespace%%"}`,
		},
		{
			name:     "multiple occurrences",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "%%correlation_id%%-%%correlation_id%%",
			expected: testCorrelationID + "-" + testCorrelationID,
		},
		{
			name:     "empty placeholder is not a match",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "%%%%",
			expected: "%%%%",
		},
		{
			name:     "stray double percent without closing is not a match",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "100%% sure",
			expected: "100%% sure",
		},
		{
			name:     "uppercase variable name does not match (lowercase whitelist only)",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "%%CORRELATION_ID%%",
			expected: "%%CORRELATION_ID%%",
		},
		{
			name:     "empty correlation_id leaves placeholder intact",
			vars:     SubstitutionVars{},
			input:    "id=%%correlation_id%%",
			expected: "id=%%correlation_id%%",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.vars.substitute(tc.input))
		})
	}
}

func TestSubstituteMap(t *testing.T) {
	vars := SubstitutionVars{CorrelationID: "uuid-1"}

	input := map[string]any{
		"top":                         "%%correlation_id%%",
		"nested":                      map[string]any{"deep": "id=%%correlation_id%%", "passthrough": "%%kube_namespace%%"},
		"slice":                       []any{"a-%%correlation_id%%", "b"},
		"non_str":                     42,
		"key_with_%%correlation_id%%": "value",
	}

	result := substituteMap(input, vars)

	assert.Equal(t, "uuid-1", result["top"], "top-level string substituted")
	assert.Equal(t, "id=uuid-1", result["nested"].(map[string]any)["deep"], "nested string substituted")
	assert.Equal(t, "%%kube_namespace%%", result["nested"].(map[string]any)["passthrough"], "unknown var passed through")
	assert.Equal(t, []any{"a-uuid-1", "b"}, result["slice"], "slice elements substituted")
	assert.Equal(t, 42, result["non_str"], "non-string leaf left untouched")

	_, keyPreserved := result["key_with_%%correlation_id%%"]
	assert.True(t, keyPreserved, "map keys are not substituted")
	assert.Len(t, result, len(input), "no extra keys introduced (would happen if keys were substituted alongside the originals)")

	assert.Equal(t, "%%correlation_id%%", input["top"], "input map not mutated")
}
