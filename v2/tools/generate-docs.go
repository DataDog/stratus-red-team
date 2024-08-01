package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "specify the docs output directory")
		os.Exit(1)
	}
	docsDirectory := os.Args[1]

	registry := stratus.GetRegistry()
	techniques := registry.ListAttackTechniques()

	// Platform => [MITRE ATT&CK tactic => list of stratus techniques]
	index := NewIndex(techniques).Values()

	if err := GenerateTechDocs(docsDirectory, techniques, index); err != nil {
		fmt.Fprintln(os.Stderr, "Could not generate techniques documentation")
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Write a single index file with all techniques. File is enconded in YAML.
	yamlIndex := filepath.Join(docsDirectory, "index.yaml")
	if err := GenerateYAML(yamlIndex, index); err != nil {
		fmt.Fprintln(os.Stderr, "Could not generate YAML index")
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
