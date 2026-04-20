package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed config.schema.json
var configSchemaJSON []byte

// SharedTerraformConfigVariable is the shared Terraform variable "config" definition,
// injected alongside technique main.tf files at warmup time.
//
//go:embed config.tf
var SharedTerraformConfigVariable []byte

// validateConfig validates raw YAML config bytes against the embedded JSON schema.
// We validate raw YAML rather than Viper's output because Viper splits dotted keys
// (e.g. technique ID "k8s.privilege-escalation.privileged-pod") into nested maps,
// which breaks schema validation.
func validateConfig(rawYAML []byte) error {
	var yamlData any
	if err := yaml.Unmarshal(rawYAML, &yamlData); err != nil {
		return fmt.Errorf("parsing config YAML: %w", err)
	}
	if yamlData == nil {
		return nil
	}

	// Round-trip through JSON to normalize yaml.v3 types into JSON-compatible types.
	jsonBytes, err := json.Marshal(yamlData)
	if err != nil {
		return fmt.Errorf("normalizing config to JSON: %w", err)
	}
	var jsonData any
	if err := json.Unmarshal(jsonBytes, &jsonData); err != nil {
		return fmt.Errorf("parsing normalized config JSON: %w", err)
	}

	// validate
	schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(configSchemaJSON))
	if err != nil {
		return fmt.Errorf("parsing config schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("config.schema.json", schema); err != nil {
		return fmt.Errorf("adding schema resource: %w", err)
	}
	compiled, err := compiler.Compile("config.schema.json")
	if err != nil {
		return fmt.Errorf("compiling config schema: %w", err)
	}
	if err := compiled.Validate(jsonData); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}
