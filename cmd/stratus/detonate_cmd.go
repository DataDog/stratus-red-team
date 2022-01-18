package main

import (
	"errors"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
	"log"
)

var detonateNoWarmup bool
var detonateCleanup bool

func buildDetonateCmd() *cobra.Command {
	detonateCmd := &cobra.Command{
		Use:   "detonate",
		Short: "Detonate one or multiple attack techniques",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("you must specify at least one attack technique")
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			doDetonateCmd(techniques, !detonateNoWarmup, detonateCleanup)
		},
	}
	detonateCmd.Flags().BoolVarP(&detonateCleanup, "cleanup", "", false, "Clean up the infrastructure that was spun up as part of the technique pre-requisites")
	detonateCmd.Flags().BoolVarP(&detonateNoWarmup, "no-warmup", "", false, "Do not spin up pre-requisite infrastructure or configuration. Requires that 'warmup' was used before.")
	return detonateCmd
}
func doDetonateCmd(techniques []*stratus.AttackTechnique, warmup bool, cleanup bool) {
	for i := range techniques {
		detonateTechnique(techniques[i], warmup, cleanup)
	}
}

func detonateTechnique(technique *stratus.AttackTechnique, warmup bool, cleanup bool) {
	stratusRunner := runner.NewRunner(technique, runner.StratusRunnerNoForce)
	err := stratusRunner.Detonate()
	if cleanup {
		defer func() {
			err := stratusRunner.CleanUp()
			if err != nil {
				log.Println("unable to clean up pre-requisites: " + err.Error())
			}
		}()
	}
	if err != nil {
		log.Fatal(err)
	}
}
