package main

import (
	"bytes"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "specify the docs output directory")
		os.Exit(1)
	}
	docsDirectory := os.Args[1]
	techniqueTemplate, _ := os.ReadFile("tools/doc.tpl")
	indexTemplate, _ := os.ReadFile("tools/index-by-platform.tpl")
	registry := stratus.GetRegistry()
	techniques := registry.ListAttackTechniques()
	funcMap := template.FuncMap{
		"ToUpper": strings.ToUpper,
		"JoinTactics": func(tactics []mitreattack.Tactic, prefix string, sep string) string {
			var result []string
			for i := range tactics {
				name := mitreattack.AttackTacticToString(tactics[i])
				result = append(result, name)
			}
			return prefix + strings.Join(result, sep)
		},
		"FormatPlatformName": FormatPlatformName,
	}

	// Platform => [MITRE ATT&CK tactic => list of stratus techniques]
	index := map[stratus.Platform]map[string][]*stratus.AttackTechnique{}

	// Pass 1: write techniques docs
	for i := range techniques {
		technique := techniques[i]
		for j := range technique.MitreAttackTactics {
			tactic := mitreattack.AttackTacticToString(technique.MitreAttackTactics[j])
			if index[technique.Platform] == nil {
				index[technique.Platform] = make(map[string][]*stratus.AttackTechnique)
			}
			if index[technique.Platform][tactic] == nil {
				index[technique.Platform][tactic] = make([]*stratus.AttackTechnique, 0)
			}
			index[technique.Platform][tactic] = append(index[technique.Platform][tactic], technique)
		}

		tpl, _ := template.New("technique").Funcs(funcMap).Parse(string(techniqueTemplate))
		result := ""
		buf := bytes.NewBufferString(result)
		formatTechniqueDescription(technique)
		err := tpl.Execute(buf, technique)
		if err != nil {
			panic(err)
		}
		dir := filepath.Join(docsDirectory, "attack-techniques", string(technique.Platform))
		if !FileExists(dir) {
			os.Mkdir(dir, 0744)
		}
		err = os.WriteFile(filepath.Join(dir, technique.ID+".md"), buf.Bytes(), 0744)
		if err != nil {
			panic(err)
		}
	}

	// Pass 2: write index per platform
	for platform, tacticsMap := range index {
		platformIndexFile := filepath.Join(docsDirectory, "attack-techniques", string(platform), "index.md")
		tpl, _ := template.New("index-by-platform").Funcs(funcMap).Parse(string(indexTemplate))
		result := ""
		buf := bytes.NewBufferString(result)
		vars := struct {
			TacticsMap map[string][]*stratus.AttackTechnique
			Platform   stratus.Platform
		}{
			tacticsMap, platform,
		}
		err := tpl.Execute(buf, vars)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(platformIndexFile, buf.Bytes(), 0744)
		if err != nil {
			panic(err)
		}
	}

	// Generate full table list
	listTemplate, _ := os.ReadFile("tools/full-list.tpl")
	listFile := filepath.Join(docsDirectory, "attack-techniques", "list.md")
	tpl, _ := template.New("index-by-platform").Funcs(funcMap).Parse(string(listTemplate))
	result := ""
	buf := bytes.NewBufferString(result)
	err := tpl.Execute(buf, techniques)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(listFile, buf.Bytes(), 0744)
	if err != nil {
		panic(err)
	}
}

func formatTechniqueDescription(technique *stratus.AttackTechnique) {
	technique.Description = strings.ReplaceAll(technique.Description, "Warm-up:", "<span style=\"font-variant: small-caps;\">Warm-up</span>:")
	technique.Description = strings.ReplaceAll(technique.Description, "Detonation:", "<span style=\"font-variant: small-caps;\">Detonation</span>:")
}

func FormatPlatformName(platform stratus.Platform) string {
	switch platform {
	case stratus.AWS:
		return "AWS"
	case stratus.Azure:
		return "Azure"
	case stratus.GCP:
		return "GCP"
	case stratus.Kubernetes:
		return "Kubernetes"
	}
	log.Fatal("unknown platform " + platform)
	return ""
}

// Utility function
func FileExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		// In case of error, we assume the file doesn't exist to make the logic simpler
		return false
	}
	return true
}
