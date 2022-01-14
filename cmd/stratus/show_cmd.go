package main

import (
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
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
		fmt.Println(techniques[i].Description)
	}
}
