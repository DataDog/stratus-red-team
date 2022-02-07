package main

import (
	"errors"
	"log"
	"os"

	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
)

var revertForce bool

func buildRevertCmd() *cobra.Command {
	detonateCmd := &cobra.Command{
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
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doRevertCmd(techniques, revertForce)
		},
	}
	detonateCmd.Flags().BoolVarP(&revertForce, "force", "f", false, "Force attempt to reverting even if the technique is not in the DETONATED state")
	return detonateCmd
}

func doRevertCmd(techniques []*stratus.AttackTechnique, force bool) {
	techniqueChan := make(chan *stratus.AttackTechnique)
	done := make(chan bool)
	for i := 0; i < maxWorkerCount; i++ {
		go func() {
			for {
				technique, more := <-techniqueChan
				if more {
					if technique.Revert == nil {
						log.Println("Warning: " + technique.ID + " has no revert function and cannot be reverted.")
						continue
					}
					stratusRunner := runner.NewRunner(technique, force)
					err := stratusRunner.Revert()
					if err != nil {
						log.Fatal(err)
					}
				} else {
					done <- true
					return
				}
			}
		}()
	}
	for i := range techniques {
		techniqueChan <- techniques[i]
	}
	close(techniqueChan)
	<-done

	doStatusCmd(techniques)
}
