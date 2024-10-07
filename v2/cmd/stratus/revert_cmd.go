package main

import (
	"errors"
	"log"
	"os"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"github.com/spf13/cobra"
)

func buildRevertCmd() *cobra.Command {
	var revertForce bool

	revertCmd := &cobra.Command{
		Use:                   "revert attack-technique-id [attack-technique-id]...",
		Short:                 "Revert the detonation of an attack technique",
		Example:               "stratus revert aws.defense-evasion.cloudtrail-stop",
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
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return getTechniquesCompletion(toComplete), cobra.ShellCompDirectiveNoFileComp
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doRevertCmd(techniques, revertForce)
		},
	}

	revertCmd.Flags().BoolVarP(&revertForce, "force", "f", false, "Force attempt to revert even if the technique is not in the DETONATED state")
	return revertCmd
}

func doRevertCmd(techniques []*stratus.AttackTechnique, force bool) {
	VerifyPlatformRequirements(techniques)
	workerCount := len(techniques)
	techniquesChan := make(chan *stratus.AttackTechnique, workerCount)
	errorsChan := make(chan error, workerCount)

	// Create workers
	for i := 0; i < workerCount; i++ {
		go revertCmdWorker(techniquesChan, errorsChan, force)
	}

	// Send attack techniques to revert
	for i := range techniques {
		techniquesChan <- techniques[i]
	}
	close(techniquesChan)

	hadError := handleErrorsChannel(errorsChan, workerCount)
	doStatusCmd(techniques)
	if hadError {
		os.Exit(1)
	}
}

func revertCmdWorker(techniques <-chan *stratus.AttackTechnique, errors chan<- error, force bool) {
	for technique := range techniques {
		if technique.Revert == nil {
			log.Println("Warning: " + technique.ID + " has no revert function and cannot be reverted.")
			errors <- nil
			continue
		}
		stratusRunner := runner.NewRunner(technique, force)
		err := stratusRunner.Revert()
		errors <- err
	}
}
