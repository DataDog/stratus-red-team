package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

func GenerateTechDocs(docsDirectory string, techniques []*stratus.AttackTechnique, index map[stratus.Platform]map[string][]*stratus.AttackTechnique) error {
	techniqueTemplate, err := os.ReadFile("tools/doc.tpl")
	if err != nil {
		return err
	}

	indexTemplate, err := os.ReadFile("tools/index-by-platform.tpl")
	if err != nil {
		return err
	}

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

	// Pass 1: write techniques docs
	for i := range techniques {
		technique := techniques[i]

		tpl, _ := template.New("technique").Funcs(funcMap).Parse(string(techniqueTemplate))
		result := ""
		buf := bytes.NewBufferString(result)
		formatTechniqueDescription(technique)
		err := tpl.Execute(buf, technique)
		if err != nil {
			return err
		}
		dir := filepath.Join(docsDirectory, "attack-techniques", string(technique.Platform))
		if !FileExists(dir) {
			os.Mkdir(dir, 0744)
		}
		err = os.WriteFile(filepath.Join(dir, technique.ID+".md"), buf.Bytes(), 0744)
		if err != nil {
			return err
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
			return err
		}
		err = os.WriteFile(platformIndexFile, buf.Bytes(), 0744)
		if err != nil {
			return err
		}
	}

	// Generate full table list
	listTemplate, _ := os.ReadFile("tools/full-list.tpl")
	listFile := filepath.Join(docsDirectory, "attack-techniques", "list.md")
	tpl, _ := template.New("index-by-platform").Funcs(funcMap).Parse(string(listTemplate))
	result := ""
	buf := bytes.NewBufferString(result)
	err = tpl.Execute(buf, techniques)
	if err != nil {
		return err
	}
	err = os.WriteFile(listFile, buf.Bytes(), 0744)
	if err != nil {
		return err
	}

	return nil
}

func formatTechniqueDescription(technique *stratus.AttackTechnique) {
	technique.Description = strings.ReplaceAll(technique.Description, "Warm-up:", "<span style=\"font-variant: small-caps;\">Warm-up</span>:")
	technique.Description = strings.ReplaceAll(technique.Description, "Detonation:", "<span style=\"font-variant: small-caps;\">Detonation</span>:")
}

func FormatPlatformName(platform stratus.Platform) string {
	n, err := platform.FormatName()
	if err != nil {
		log.Fatal("unknown platform " + platform)
	}
	return n
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
