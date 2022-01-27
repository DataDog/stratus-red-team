package main

import (
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"log"
	"strings"
)

var listPlatform string
var listMitreAttackTactic string

func buildListCmd() *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List attack techniques",
		Example: strings.Join([]string{
			"stratus list",
			"stratus list --platform aws --mitre-attack-tactic persistence",
		}, "\n"),
		Run: func(cmd *cobra.Command, args []string) {
			doListCmd(listMitreAttackTactic, listPlatform)
		},
	}
	listCmd.Flags().StringVarP(&listPlatform, "platform", "", "", "Filter on specific platform")
	listCmd.Flags().StringVarP(&listMitreAttackTactic, "mitre-attack-tactic", "", "", "Filter on a specific MITRE ATT&CK tactic.")
	return listCmd
}

func doListCmd(mitreAttackTactic string, platform string) {
	filter := stratus.AttackTechniqueFilter{}
	if platform != "" {
		platform, err := stratus.PlatformFromString(platform)
		if err != nil {
			log.Fatal(err)
		}
		filter.Platform = platform
	}
	if mitreAttackTactic != "" {
		tactic, err := mitreattack.AttackTacticFromString(mitreAttackTactic)
		if err != nil {
			log.Fatal(err)
		}
		filter.Tactic = tactic
	}
	techniques := stratus.GetRegistry().GetAttackTechniques(&filter)
	t := GetDisplayTable()
	t.AppendHeader(table.Row{"Technique ID", "Technique name", "Platform", "MITRE ATT&CK Tactic"})

	for i := range techniques {
		displayName := techniques[i].ID
		if friendlyName := techniques[i].FriendlyName; friendlyName != "" {
			displayName = friendlyName
		}
		t.AppendRow(table.Row{
			techniques[i].ID,
			displayName,
			techniques[i].Platform,
			getTacticsString(techniques[i].MitreAttackTactics),
		})
	}

	fmt.Println()
	fmt.Println(color.CyanString("View the list of all available attack techniques at: https://stratus-red-team.cloud/attack-techniques/list/\n"))
	t.Render()
}

func getTacticsString(tactics []mitreattack.Tactic) string {
	var names []string
	for i := range tactics {
		names = append(names, mitreattack.AttackTacticToString(tactics[i]))
	}

	return strings.Join(names, "\n")
}
