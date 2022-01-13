package main

import (
	"errors"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/spf13/cobra"
)

var flagPlatform string
var flagMitreAttackTactic string
var dontCleanUpPrerequisiteResources bool
var dontWarmUp bool

var rootCmd = &cobra.Command{
	Use: "stratus-red-team",
}

func init() {
	listCmd := buildListCmd()
	showCmd := buildShowCmd()
	warmupCmd := buildWarmupCmd()
	detonateCmd := buildDetonateCmd()

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(warmupCmd)
	rootCmd.AddCommand(detonateCmd)
}

func buildListCmd() *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List attack techniques",
		Run: func(cmd *cobra.Command, args []string) {
			do_list_cmd(flagMitreAttackTactic, flagPlatform)
		},
	}
	listCmd.Flags().StringVarP(&flagPlatform, "platform", "", "", "Filter on specific platform")
	listCmd.Flags().StringVarP(&flagMitreAttackTactic, "mitre-attack-tactic", "", "", "Filter on a specific MITRE ATT&CK tactic.")
	return listCmd
}

func buildShowCmd() *cobra.Command {
	warmupCmd := &cobra.Command{
		Use:   "show",
		Short: "Displays detailed information about an attack technique.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("you must specify at least one attack technique")
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			techniques, _ := resolveTechniques(args)
			do_show_cmd(techniques)
		},
	}
	return warmupCmd
}

func resolveTechniques(names []string) ([]*stratus.AttackTechnique, error) {
	var result []*stratus.AttackTechnique
	for i := range names {
		technique := stratus.GetRegistry().GetAttackTechniqueByName(names[i])
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
			do_warmup_cmd(techniques, !dontWarmUp)
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
			do_detonate_cmd(techniques, !dontWarmUp, !dontCleanUpPrerequisiteResources)
		},
	}
	detonateCmd.Flags().BoolVarP(&dontCleanUpPrerequisiteResources, "no-cleanup", "", false, "Do not clean up the infrastructure that was spun up as part of the technique pre-requisites")
	detonateCmd.Flags().BoolVarP(&dontWarmUp, "no-warmup", "", false, "Do not spin up pre-requisite infrastructure or configuration. Requires that 'warmup' was used before.")
	return detonateCmd
}

func main() {
	rootCmd.Execute()
}
