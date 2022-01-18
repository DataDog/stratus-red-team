package main

import (
	"errors"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
	"log"
)

var forceWarmup bool

func buildWarmupCmd() *cobra.Command {
	warmupCmd := &cobra.Command{
		Use:   "warmup",
		Short: "\"Warm up\" an attack technique by spinning up the pre-requisite infrastructure or configuration, without detonating it",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("you must specify at least one attack technique")
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doWarmupCmd(techniques)
		},
	}
	warmupCmd.Flags().BoolVarP(&forceWarmup, "force", "f", false, "Force re-ensuring the pre-requisite infrastructure or configuration is up to date")
	return warmupCmd
}

func doWarmupCmd(techniques []*stratus.AttackTechnique) {
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], forceWarmup)
		_, err := runner.WarmUp()
		if err != nil {
			log.Fatal(err)
		}
	}
}
