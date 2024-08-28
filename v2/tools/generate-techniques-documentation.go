package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

type DetonationLogs struct {
	EventNames     []string
	RawLogs        string
	EventNameLines []int
}

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
		templateInput := struct {
			Technique      *stratus.AttackTechnique
			DetonationLogs *DetonationLogs
		}{
			Technique:      technique,
			DetonationLogs: findDetonationLogs(technique),
		}
		err := tpl.Execute(buf, templateInput)
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

func findDetonationLogs(technique *stratus.AttackTechnique) *DetonationLogs {
	data, err := os.ReadFile("../docs/detonation-logs/" + technique.ID + ".json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // no detonation logs
		}
		log.Fatalf("unable to read detonation logs for technique %s: %v", technique.ID, err)
	}

	var logs []map[string]interface{}
	if err := json.Unmarshal(data, &logs); err != nil {
		println("unable to parse JSON detonation logs for technique " + technique.ID + ": " + err.Error())
		return nil
	}

	// Unique event names
	var eventNamesSet = make(map[string]bool)
	for _, event := range logs {
		eventName := fmt.Sprintf("%s:%s", strings.TrimSuffix(event["eventSource"].(string), ".amazonaws.com"), event["eventName"].(string))
		if _, ok := eventNamesSet[eventName]; !ok {
			eventNamesSet[eventName] = true
		}
	}

	var eventNames []string
	for k := range eventNamesSet {
		eventNames = append(eventNames, k)
	}
	sort.Strings(eventNames)

	rawLogs := strings.ReplaceAll(string(data), "\n", "\n\t") // indent for markdown
	var eventNameLines []int
	for lineNo, line := range strings.Split(rawLogs, "\n") {
		if strings.Contains(line, "\"eventName\":") {
			eventNameLines = append(eventNameLines, lineNo+1)
		}
	}

	return &DetonationLogs{
		EventNames:     eventNames,
		RawLogs:        rawLogs,
		EventNameLines: eventNameLines,
	}
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
