package main

import (
	"errors"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
	"log"
	"os"
)

var forceWarmup bool

func buildWarmupCmd() *cobra.Command {
	warmupCmd := &cobra.Command{
		Use:                   "warmup attack-technique-id [attack-technique-id]...",
		Short:                 "\"Warm up\" an attack technique by spinning up the prerequisite infrastructure or configuration, without detonating it",
		Example:               "stratus warmup aws.defense-evasion.stop-cloudtrail",
		DisableFlagsInUseLine: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.Help()
				os.Exit(0)
			}
			return nil
		},
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
	warmupCmd.Flags().BoolVarP(&forceWarmup, "force", "f", false, "Force re-ensuring the prerequisite infrastructure or configuration is up to date")
	return warmupCmd
}

func doWarmupCmd(techniques []*stratus.AttackTechnique) {
	for i := range techniques {
		stratusRunner := runner.NewRunner(techniques[i], forceWarmup)
		_, err := stratusRunner.WarmUp()
		if err != nil {
			log.Fatal(err)
		}
	}
}
