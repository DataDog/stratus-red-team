package main

import (
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
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
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return getTechniquesCompletion(toComplete), cobra.ShellCompDirectiveNoFileComp
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
		fmt.Println(techniques[i].Description)
	}
}
