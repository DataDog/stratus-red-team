package main

import (
	"errors"
	"fmt"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques"
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/spf13/cobra"
	"log"
)

var flagPlatform string
var dontCleanUpPrerequisiteResources bool
var dontWarmUp bool

var rootCmd = &cobra.Command{
	Use: "stratus-red-team",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		fmt.Println("Main entrypoint")
	},
}

func init() {
	listCmd := buildListCmd()
	warmupCmd := buildWarmupCmd()
	detonateCmd := buildDetonateCmd()

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(warmupCmd)
	rootCmd.AddCommand(detonateCmd)
}

func buildListCmd() *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all attack techniques",
		Run: func(cmd *cobra.Command, args []string) {
			var techniques []*stratus.AttackTechnique
			if flagPlatform == "" {
				techniques = stratus.ListAttackTechniques()
			} else {
				platform, err := stratus.PlatformFromString(flagPlatform)
				if err != nil {
					log.Fatal(err)
				}
				techniques = stratus.GetAttackTechniquesForPlatform(platform)
			}
			for i := range techniques {
				fmt.Println(techniques[i])
			}
		},
	}
	listCmd.Flags().StringVarP(&flagPlatform, "platform", "", "", "Filter on specific platform")

	return listCmd
}

func resolveTechniques(names []string) ([]*stratus.AttackTechnique, error) {
	var result []*stratus.AttackTechnique
	for i := range names {
		technique := stratus.GetAttackTechniqueByName(names[i])
		if technique == nil {
			return nil, errors.New("unknown technique name " + names[i])
		}
		result = append(result, technique)
	}
	return result, nil
}

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
			for i := range techniques {
				_, err := runner.WarmUp(techniques[i], !dontWarmUp)
				if err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	return warmupCmd
}

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
			options := runner.RunOptions{Warmup: !dontWarmUp, Cleanup: !dontCleanUpPrerequisiteResources}
			for i := range techniques {
				err := runner.RunAttackTechnique(techniques[i], options)
				if err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	detonateCmd.Flags().BoolVarP(&dontCleanUpPrerequisiteResources, "no-cleanup", "", false, "Do not clean up the infrastructure that was spun up as part of the technique pre-requisites")
	detonateCmd.Flags().BoolVarP(&dontWarmUp, "no-warmup", "", false, "Do not spin up pre-requisite infrastructure or configuration. Requires that 'warmup' was used before.")
	return detonateCmd
}

func main() {
	rootCmd.Execute()
}
