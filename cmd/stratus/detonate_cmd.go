package main

import (
	"errors"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"github.com/spf13/cobra"
	"log"
	"os"
	"strings"
)

var detonateForce bool
var detonateCleanup bool

func buildDetonateCmd() *cobra.Command {
	detonateCmd := &cobra.Command{
		Use:   "detonate attack-technique-id [attack-technique-id]...",
		Short: "Detonate one or multiple attack techniques",
		Example: strings.Join([]string{
			"stratus detonate aws.defense-evasion.stop-cloudtrail",
			"stratus detonate aws.defense-evasion.stop-cloudtrail --cleanup",
		}, "\n"),
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
			doDetonateCmd(techniques, detonateCleanup)
		},
	}
	detonateCmd.Flags().BoolVarP(&detonateCleanup, "cleanup", "", false, "Clean up the infrastructure that was spun up as part of the technique prerequisites")
	//detonateCmd.Flags().BoolVarP(&detonateNoWarmup, "no-warmup", "", false, "Do not spin up prerequisite infrastructure or configuration. Requires that 'warmup' was used before.")
	detonateCmd.Flags().BoolVarP(&detonateForce, "force", "f", false, "Force detonation in cases where the technique is not idempotent and has already been detonated")

	return detonateCmd
}
func doDetonateCmd(techniques []*stratus.AttackTechnique, cleanup bool) {
	for i := range techniques {
		detonateTechnique(techniques[i], cleanup)
	}
}

func detonateTechnique(technique *stratus.AttackTechnique, cleanup bool) {
	stratusRunner := runner.NewRunner(technique, detonateForce)
	err := stratusRunner.Detonate()
	if cleanup {
		defer func() {
			err := stratusRunner.CleanUp()
			if err != nil {
				log.Println("unable to clean up prerequisites: " + err.Error())
			}
		}()
	}
	if err != nil {
		log.Fatal(err)
	}
}
