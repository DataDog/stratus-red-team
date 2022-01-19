package main

import (
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
	"log"
)

var forceCleanup bool

func buildCleanupCmd() *cobra.Command {
	cleanupCmd := &cobra.Command{
		Use:     "cleanup",
		Aliases: []string{"clean"},
		Short:   "Cleans up any leftover infrastructure or configuration from a TTP.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil // no technique specified == all techniques
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				techniques, _ := resolveTechniques(args)
				doCleanupCmd(techniques)
			} else {
				doCleanupCmd(stratus.GetRegistry().ListAttackTechniques())
			}
		},
	}
	cleanupCmd.Flags().BoolVarP(&forceCleanup, "force", "f", false, "Force cleanup even if the technique is already COLD")
	return cleanupCmd
}

func doCleanupCmd(techniques []*stratus.AttackTechnique) {
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], forceCleanup)
		err := runner.CleanUp()
		if err != nil {
			log.Println("Failed to clean up: " + err.Error())
			// continue cleaning up other techniques
		}
	}
	doStatusCmd(techniques)
}
