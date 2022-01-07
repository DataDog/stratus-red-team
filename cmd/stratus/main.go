package main

import (
	"fmt"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques"
	"github.com/datadog/stratus-red-team/internal/registrations"
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/attacktechnique"
	"github.com/spf13/cobra"
	"log"
)

var platform string
var attackTechniqueNames []string
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
	//fmt.Println(registrations.ListAttackTechniques())
	listCmd := buildListCmd()
	warmupCmd := buildWarmupCmd()
	detonateCmd := buildDetonateCmd()

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(warmupCmd)
	rootCmd.AddCommand(detonateCmd)

	/*tfinstaller := &tfreleases.ExactVersion{
		Product: hcproduct.Terraform,
		Version: version.Must(version.NewVersion("1.1.2")),
	}
	log.Println("Installing Terraform")
	execPath, err := tfinstaller.Install(context.Background())
	if err != nil {
		log.Fatalf("error installing Terraform: %s", err)
	}

	tf, err := tfexec.NewTerraform("/tmp/tf", execPath)

	log.Println("Initializing Terraform")
	tf.Init(context.Background())

	log.Println("Applying Terraform")
	err = tf.Apply(context.Background(), tfexec.Parallelism(1))
	if err != nil {
		log.Fatal("Unable to run tf apply: " + err.Error())
	}

	log.Println("Destroying Terraform")
	err = tf.Destroy(context.Background())
	*/
}

func buildListCmd() *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all attack techniques",
		Run: func(cmd *cobra.Command, args []string) {
			var techniques []attacktechnique.AttackTechnique
			if platform == "" {
				techniques = registrations.ListAttackTechniques()
			} else {
				techniques = registrations.GetAttackTechniquesForPlatform(platform)
			}
			for i := range techniques {
				fmt.Println(techniques[i])
			}
		},
	}
	listCmd.Flags().StringVarP(&platform, "platform", "", "", "Filter on specific platform")

	return listCmd
}

func buildWarmupCmd() *cobra.Command {
	warmupCmd := &cobra.Command{
		Use:   "warmup",
		Short: "\"Warm up\" an attack technique by spinning up the pre-requisite infrastrcuture or configuration, without detonating it",
		Run: func(cmd *cobra.Command, args []string) {
			if len(attackTechniqueNames) == 0 {
				log.Fatal("You must specify at least one technique ID to detonate")
				return
			}
			for i := range attackTechniqueNames {
				technique := registrations.GetAttackTechniqueByName(attackTechniqueNames[i])
				if technique == nil {
					log.Fatal("Unknown attack technique: " + attackTechniqueNames[i])
					return
				}
				_, err := runner.WarmUp(technique, !dontWarmUp)
				if err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	warmupCmd.Flags().StringArrayVarP(&attackTechniqueNames, "techniques", "", []string{}, "Techniques to warmup")
	return warmupCmd
}

func buildDetonateCmd() *cobra.Command {
	detonateCmd := &cobra.Command{
		Use:   "detonate",
		Short: "Detonate one or multiple attack techniques",
		Run: func(cmd *cobra.Command, args []string) {
			if len(attackTechniqueNames) == 0 {
				log.Fatal("You must specify at least one technique ID to detonate")
				return
			}
			for i := range attackTechniqueNames {
				technique := registrations.GetAttackTechniqueByName(attackTechniqueNames[i])
				if technique == nil {
					log.Fatal("Unknown attack technique: " + attackTechniqueNames[i])
					return
				}
				err := runner.RunAttackTechnique(technique, !dontCleanUpPrerequisiteResources, !dontWarmUp)
				if err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	detonateCmd.Flags().StringArrayVarP(&attackTechniqueNames, "techniques", "", []string{}, "Techniques to detonate")
	detonateCmd.Flags().BoolVarP(&dontCleanUpPrerequisiteResources, "no-cleanup", "", false, "Do not clean up the infrastructure that was spun up as part of the technique pre-requisites")
	detonateCmd.Flags().BoolVarP(&dontWarmUp, "no-warmup", "", false, "Do not spin up pre-requisite infrastructure or configuration. Requires that 'warmup' was used before.")
	return detonateCmd
}

func main() {
	rootCmd.Execute()
}
