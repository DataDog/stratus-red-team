package main

import (
	"errors"
	"log"

	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
)

var flagForceCleanup bool
var flagCleanupAll bool

func buildCleanupCmd() *cobra.Command {
	cleanupCmd := &cobra.Command{
		Use:                   "cleanup [attack-technique-id]... | --all",
		Aliases:               []string{"clean"},
		Short:                 "Cleans up any leftover infrastructure or configuration from a TTP.",
		Example:               "stratus cleanup aws.defense-evasion.cloudtrail-stop\nstratus cleanup --all",
		DisableFlagsInUseLine: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && flagCleanupAll {
				if !flagCleanupAll {
					return errors.New("pass the ID of the technique to clean up, or --all")
				}
				return nil
			}

			// Ensure the technique IDs are valid
			_, err := resolveTechniques(args)

			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				techniques, _ := resolveTechniques(args)
				doCleanupCmd(techniques)
				return nil
			} else if flagCleanupAll {
				// clean up all techniques that are not in the COLD state
				doCleanupAllCmd()
				return nil
			} else {
				return errors.New("pass the ID of the technique to clean up, or --all")
			}
		},
	}
	cleanupCmd.Flags().BoolVarP(&flagForceCleanup, "force", "f", false, "Force cleanup even if the technique is already COLD")
	cleanupCmd.Flags().BoolVarP(&flagCleanupAll, "all", "", false, "Clean up all techniques that are not in COLD state")
	return cleanupCmd
}

func doCleanupCmd(techniques []*stratus.AttackTechnique) {
	techniqueChan := make(chan *stratus.AttackTechnique)
	done := make(chan bool)
	for i := 0; i < maxWorkerCount; i++ {
		go func() {
			for {
				technique, more := <-techniqueChan
				if more {
					stratusRunner := runner.NewRunner(technique, forceWarmup)
					err := stratusRunner.CleanUp()
					if err != nil {
						log.Println("Failed to clean up: " + err.Error())
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

func doCleanupAllCmd() {
	log.Println("Cleaning up all techniques that have been warmed-up or detonated")
	availableTechniques := stratus.GetRegistry().ListAttackTechniques()
	doCleanupCmd(availableTechniques)
}
