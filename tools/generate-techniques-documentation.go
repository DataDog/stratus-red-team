package main

import (
	"bytes"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

func main() {
	techniqueTemplate, _ := os.ReadFile("tools/doc.tpl")
	registry := stratus.GetRegistry()
	techniques := registry.ListAttackTechniques()
	funcMap := template.FuncMap{
		"ToUpper": strings.ToUpper,
		"JoinTactics": func(tactics []mitreattack.Tactic) string {
			result := []string{}
			for i := range tactics {
				name := mitreattack.AttackTacticToString(tactics[i])
				result = append(result, name)
			}
			return "- " + strings.Join(result, "\n- ")
		},
	}
	for i := range techniques {
		tpl, _ := template.New("technique").Funcs(funcMap).Parse(string(techniqueTemplate))
		result := ""
		buf := bytes.NewBufferString(result)
		err := tpl.Execute(buf, techniques[i])
		if err != nil {
			panic(err)
		}
		dir := filepath.Join("docs", "ttps", string(techniques[i].Platform))
		if !utils.FileExists(dir) {
			os.Mkdir(dir, 0744)
		}
		err = os.WriteFile(filepath.Join(dir, techniques[i].ID+".md"), []byte(buf.String()), 0744)
		if err != nil {
			panic(err)
		}
	}
}
