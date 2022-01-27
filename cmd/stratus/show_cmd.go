package main

import (
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func buildShowCmd() *cobra.Command {
	warmupCmd := &cobra.Command{
		Use:   "show",
		Short: "Displays detailed information about an attack technique.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("you must specify at least one attack technique")
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doShowCmd(techniques)
		},
	}
	return warmupCmd
}

func doShowCmd(techniques []*stratus.AttackTechnique) {
	for i := range techniques {
		fmt.Println()
		fmt.Println(color.CyanString("View documentation at: " + buildDocsUrl(techniques[i])))
		fmt.Println(techniques[i].Description)
	}
}

func buildDocsUrl(technique *stratus.AttackTechnique) string {
	return fmt.Sprintf(
		"https://stratus-red-team.cloud/attack-techniques/%s/%s/",
		string(technique.Platform),
		technique.ID,
	)
}
