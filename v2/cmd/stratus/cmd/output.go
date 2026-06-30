package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

// Supported values for the global --output/-o flag.
const (
	OutputFormatTable = "table"
	OutputFormatJSON  = "json"
)

// outputFormat holds the value of the global --output/-o flag. It defaults to
// "table" to preserve the historical human-readable output.
var outputFormat = OutputFormatTable

// validateOutputFormat ensures the user-supplied output format is supported.
func validateOutputFormat(format string) error {
	switch format {
	case OutputFormatTable, OutputFormatJSON:
		return nil
	default:
		return fmt.Errorf("unsupported output format %q (must be one of: %s, %s)", format, OutputFormatTable, OutputFormatJSON)
	}
}

// isJSONOutput returns true when the user requested JSON output.
func isJSONOutput() bool {
	return outputFormat == OutputFormatJSON
}

// outputJSON writes v to w as indented JSON, followed by a trailing newline.
func outputJSON(w io.Writer, v interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(v)
}

// The structs below define a stable JSON contract for the CLI. They are
// intentionally decoupled from stratus.AttackTechnique, which carries fields
// that must not (and cannot) be serialized — the Detonate/Revert closures and
// the embedded Terraform code.

type techniqueListItemJSON struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Platform           string   `json:"platform"`
	IsSlow             bool     `json:"isSlow"`
	IsIdempotent       bool     `json:"isIdempotent"`
	MitreAttackTactics []string `json:"mitreAttackTactics"`
}

type techniqueStatusJSON struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type techniqueMappingJSON struct {
	Name string `json:"name"`
	ID   string `json:"id"`
	URL  string `json:"url"`
}

type frameworkMappingJSON struct {
	Framework  string                 `json:"framework"`
	Techniques []techniqueMappingJSON `json:"techniques"`
}

type techniqueDetailJSON struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	Platform           string                 `json:"platform"`
	IsSlow             bool                   `json:"isSlow"`
	IsIdempotent       bool                   `json:"isIdempotent"`
	MitreAttackTactics []string               `json:"mitreAttackTactics"`
	Description        string                 `json:"description"`
	Detection          string                 `json:"detection"`
	FrameworkMappings  []frameworkMappingJSON `json:"frameworkMappings,omitempty"`
}

func tacticsToStrings(tactics []mitreattack.Tactic) []string {
	result := make([]string, 0, len(tactics))
	for i := range tactics {
		result = append(result, mitreattack.AttackTacticToString(tactics[i]))
	}
	return result
}

func toFrameworkMappingsJSON(mappings []stratus.FrameworkMappings) []frameworkMappingJSON {
	if len(mappings) == 0 {
		return nil
	}
	result := make([]frameworkMappingJSON, 0, len(mappings))
	for i := range mappings {
		techniques := make([]techniqueMappingJSON, 0, len(mappings[i].Techniques))
		for j := range mappings[i].Techniques {
			techniques = append(techniques, techniqueMappingJSON{
				Name: mappings[i].Techniques[j].Name,
				ID:   mappings[i].Techniques[j].ID,
				URL:  mappings[i].Techniques[j].URL,
			})
		}
		result = append(result, frameworkMappingJSON{
			Framework:  string(mappings[i].Framework),
			Techniques: techniques,
		})
	}
	return result
}

// toTechniqueListJSON maps attack techniques to their JSON list representation.
func toTechniqueListJSON(techniques []*stratus.AttackTechnique) []techniqueListItemJSON {
	result := make([]techniqueListItemJSON, 0, len(techniques))
	for i := range techniques {
		result = append(result, techniqueListItemJSON{
			ID:                 techniques[i].ID,
			Name:               techniques[i].FriendlyName,
			Platform:           string(techniques[i].Platform),
			IsSlow:             techniques[i].IsSlow,
			IsIdempotent:       techniques[i].IsIdempotent,
			MitreAttackTactics: tacticsToStrings(techniques[i].MitreAttackTactics),
		})
	}
	return result
}

// toTechniqueDetailJSON maps a single attack technique to its detailed JSON
// representation, used by the `show` command.
func toTechniqueDetailJSON(technique *stratus.AttackTechnique) techniqueDetailJSON {
	return techniqueDetailJSON{
		ID:                 technique.ID,
		Name:               technique.FriendlyName,
		Platform:           string(technique.Platform),
		IsSlow:             technique.IsSlow,
		IsIdempotent:       technique.IsIdempotent,
		MitreAttackTactics: tacticsToStrings(technique.MitreAttackTactics),
		Description:        technique.Description,
		Detection:          technique.Detection,
		FrameworkMappings:  toFrameworkMappingsJSON(technique.FrameworkMappings),
	}
}
