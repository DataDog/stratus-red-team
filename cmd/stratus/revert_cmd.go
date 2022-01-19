package main

import (
	"errors"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
	"log"
)

var revertForce bool

func buildRevertCmd() *cobra.Command {
	detonateCmd := &cobra.Command{
		Use:   "revert",
		Short: "Revert the detonation of an attack technique",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("you must specify at least one attack technique")
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doRevertCmd(techniques, revertForce)
		},
	}
	detonateCmd.Flags().BoolVarP(&revertForce, "force", "f", false, "Force attempt to reverting even if the technique is not in the DETONATED state")
	return detonateCmd
}

func doRevertCmd(techniques []*stratus.AttackTechnique, force bool) {
	for i := range techniques {
		stratusRunner := runner.NewRunner(techniques[i], force)
		err := stratusRunner.Revert()
		if err != nil {
			log.Fatal(err)
		}
	}

	doStatusCmd(techniques)
}
