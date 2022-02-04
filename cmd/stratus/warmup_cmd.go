package main

import (
	"errors"
	"log"
	"os"

	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
)

var forceWarmup bool

func buildWarmupCmd() *cobra.Command {
	warmupCmd := &cobra.Command{
		Use:                   "warmup attack-technique-id [attack-technique-id]...",
		Short:                 "\"Warm up\" an attack technique by spinning up the prerequisite infrastructure or configuration, without detonating it",
		Example:               "stratus warmup aws.defense-evasion.cloudtrail-stop",
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
	techniqueChan := make(chan *stratus.AttackTechnique)
	done := make(chan bool)
	for i := 0; i < workerCount; i++ {
		go func() {
			for {
				technique, more := <-techniqueChan
				if more {
					stratusRunner := runner.NewRunner(technique, forceWarmup)
					_, err := stratusRunner.WarmUp()
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
}
