package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleTechnique() *stratus.AttackTechnique {
	return &stratus.AttackTechnique{
		ID:                 "aws.persistence.sample",
		FriendlyName:       "Sample Technique",
		Platform:           stratus.AWS,
		IsSlow:             true,
		IsIdempotent:       false,
		Description:        "A description containing <html> & ampersands",
		Detection:          "Look for CloudTrail events such as foo & bar",
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence, mitreattack.CredentialAccess},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{Name: "Create Account", ID: "TA0003", URL: "https://example.com/ta0003"},
				},
			},
		},
	}
}

func TestValidateOutputFormat(t *testing.T) {
	assert.NoError(t, validateOutputFormat(OutputFormatTable))
	assert.NoError(t, validateOutputFormat(OutputFormatJSON))
	assert.Error(t, validateOutputFormat("yaml"))
	assert.Error(t, validateOutputFormat(""))
	assert.Error(t, validateOutputFormat("JSON")) // case-sensitive on purpose
}

func TestIsJSONOutput(t *testing.T) {
	original := outputFormat
	defer func() { outputFormat = original }()

	outputFormat = OutputFormatJSON
	assert.True(t, isJSONOutput())
	outputFormat = OutputFormatTable
	assert.False(t, isJSONOutput())
}

func TestOutputJSONIsValidIndentedAndDoesNotEscapeHTML(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, outputJSON(&buf, map[string]string{"key": "a & b <c>"}))

	out := buf.String()
	assert.True(t, strings.HasSuffix(out, "\n"), "output should end with a newline")
	assert.Contains(t, out, "  ", "output should be indented")
	// SetEscapeHTML(false) keeps &, <, > literal so consumers see real values
	assert.Contains(t, out, "a & b <c>")
	assert.NotContains(t, out, "\\u0026")

	// And it must still be valid JSON
	var roundTrip map[string]string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &roundTrip))
	assert.Equal(t, "a & b <c>", roundTrip["key"])
}

func TestToTechniqueListJSON(t *testing.T) {
	technique := sampleTechnique()
	items := toTechniqueListJSON([]*stratus.AttackTechnique{technique})

	require.Len(t, items, 1)
	item := items[0]
	assert.Equal(t, "aws.persistence.sample", item.ID)
	assert.Equal(t, "Sample Technique", item.Name)
	assert.Equal(t, "AWS", item.Platform)
	assert.True(t, item.IsSlow)
	assert.False(t, item.IsIdempotent)
	assert.Equal(t, []string{
		mitreattack.AttackTacticToString(mitreattack.Persistence),
		mitreattack.AttackTacticToString(mitreattack.CredentialAccess),
	}, item.MitreAttackTactics)
}

func TestToTechniqueListJSONEmptyTacticsSerializesToEmptyArray(t *testing.T) {
	technique := &stratus.AttackTechnique{ID: "aws.x", Platform: stratus.AWS}
	var buf bytes.Buffer
	require.NoError(t, outputJSON(&buf, toTechniqueListJSON([]*stratus.AttackTechnique{technique})))
	// Empty tactics must render as [] (not null) so downstream parsers are stable
	assert.Contains(t, buf.String(), `"mitreAttackTactics": []`)
}

func TestListJSONRoundTrip(t *testing.T) {
	technique := sampleTechnique()
	var buf bytes.Buffer
	require.NoError(t, outputJSON(&buf, toTechniqueListJSON([]*stratus.AttackTechnique{technique})))

	var decoded []techniqueListItemJSON
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, technique.ID, decoded[0].ID)
	assert.Equal(t, technique.FriendlyName, decoded[0].Name)
	assert.Len(t, decoded[0].MitreAttackTactics, 2)
}

func TestToTechniqueDetailJSON(t *testing.T) {
	detail := toTechniqueDetailJSON(sampleTechnique())

	assert.Equal(t, "aws.persistence.sample", detail.ID)
	assert.Equal(t, "Sample Technique", detail.Name)
	assert.Equal(t, "AWS", detail.Platform)
	assert.Contains(t, detail.Description, "ampersands")
	assert.Contains(t, detail.Detection, "CloudTrail")
	require.Len(t, detail.FrameworkMappings, 1)
	assert.Equal(t, string(stratus.ThreatTechniqueCatalogAWS), detail.FrameworkMappings[0].Framework)
	require.Len(t, detail.FrameworkMappings[0].Techniques, 1)
	assert.Equal(t, "TA0003", detail.FrameworkMappings[0].Techniques[0].ID)
	assert.Equal(t, "Create Account", detail.FrameworkMappings[0].Techniques[0].Name)
}

func TestToTechniqueDetailJSONOmitsEmptyFrameworkMappings(t *testing.T) {
	technique := &stratus.AttackTechnique{ID: "aws.x", Platform: stratus.AWS}
	var buf bytes.Buffer
	require.NoError(t, outputJSON(&buf, toTechniqueDetailJSON(technique)))
	// frameworkMappings has omitempty: absent when there are none
	assert.NotContains(t, buf.String(), "frameworkMappings")
}
