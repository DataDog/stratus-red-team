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
			name:     "known field",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "id=<% .CorrelationID %>",
			expected: "id=" + testCorrelationID,
		},
		{
			name:     "known field, no spaces between delims and field",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "id=<%.CorrelationID%>",
			expected: "id=" + testCorrelationID,
		},
		{
			name:     "multiple occurrences",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "<%.CorrelationID%>-<%.CorrelationID%>",
			expected: testCorrelationID + "-" + testCorrelationID,
		},
		{
			name:     "embedded in JSON",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    `{"id":"<%.CorrelationID%>"}`,
			expected: `{"id":"` + testCorrelationID + `"}`,
		},
		{
			name:     "DD Agent autodiscovery vars are not template syntax, pass through",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    `{"ns":"%%kube_namespace%%"}`,
			expected: `{"ns":"%%kube_namespace%%"}`,
		},
		{
			name:     "unknown field renders as no-value-with-empty-fallback",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "<%.Unknown%>",
			expected: "<%.Unknown%>", // Execute errors → return original
		},
		{
			name:     "malformed template passes through",
			vars:     SubstitutionVars{CorrelationID: testCorrelationID},
			input:    "<%.unterminated",
			expected: "<%.unterminated", // Parse errors → return original
		},
		{
			name:     "empty CorrelationID renders empty",
			vars:     SubstitutionVars{},
			input:    "id=<%.CorrelationID%>",
			expected: "id=",
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
		"top":                         "<%.CorrelationID%>",
		"nested":                      map[string]any{"deep": "id=<%.CorrelationID%>", "passthrough": "%%kube_namespace%%"},
		"slice":                       []any{"a-<%.CorrelationID%>", "b"},
		"non_str":                     42,
		"key_with_<%.CorrelationID%>": "value",
	}

	result := substituteMap(input, vars)

	assert.Equal(t, "uuid-1", result["top"], "top-level string substituted")
	assert.Equal(t, "id=uuid-1", result["nested"].(map[string]any)["deep"], "nested string substituted")
	assert.Equal(t, "%%kube_namespace%%", result["nested"].(map[string]any)["passthrough"], "non-template content untouched")
	assert.Equal(t, []any{"a-uuid-1", "b"}, result["slice"], "slice elements substituted")
	assert.Equal(t, 42, result["non_str"], "non-string leaf left untouched")

	_, keyPreserved := result["key_with_<%.CorrelationID%>"]
	assert.True(t, keyPreserved, "map keys are not substituted")
	assert.Len(t, result, len(input), "no extra keys introduced")

	assert.Equal(t, "<%.CorrelationID%>", input["top"], "input map not mutated")
}
