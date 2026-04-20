package main

import (
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
)

// LoggingTerraformManager wraps the default TerraformManager to add
// logging around Terraform operations.
type LoggingTerraformManager struct {
	inner stratusrunner.TerraformManager
}

func (m *LoggingTerraformManager) Initialize() {
	m.inner.Initialize()
}

func (m *LoggingTerraformManager) TerraformInitAndApply(
	directory string,
	variables map[string]string,
) (map[string]string, error) {
	log.Printf("[logging-wrapper] terraform apply starting in %s", directory)
	outputs, err := m.inner.TerraformInitAndApply(directory, variables)
	if err != nil {
		log.Printf("[logging-wrapper] terraform apply failed: %v", err)
	} else {
		log.Printf("[logging-wrapper] terraform apply succeeded with %d outputs", len(outputs))
	}
	return outputs, err
}

func (m *LoggingTerraformManager) TerraformDestroy(
	directory string,
	variables map[string]string,
) error {
	log.Printf("[logging-wrapper] terraform destroy starting in %s", directory)
	err := m.inner.TerraformDestroy(directory, variables)
	if err != nil {
		log.Printf("[logging-wrapper] terraform destroy failed: %v", err)
	} else {
		log.Printf("[logging-wrapper] terraform destroy succeeded")
	}
	return err
}

/*
This example shows how to use runner options to inject a custom dependency.
Here we wrap the default TerraformManager with a logging decorator, then
pass it to the runner via WithTerraformManager.
*/
func main() {
	ttp := stratus.GetRegistry().GetAttackTechniqueByName("aws.defense-evasion.cloudtrail-stop")

	// Build the default TerraformManager, then wrap it
	defaultTfManager := stratusrunner.NewTerraformManager("/tmp/stratus-terraform", "example-agent")
	loggingTfManager := &LoggingTerraformManager{inner: defaultTfManager}

	stratusRunner := stratusrunner.NewRunner(
		ttp,
		stratusrunner.StratusRunnerNoForce,
		stratusrunner.WithTerraformManager(loggingTfManager),
	)

	_, err := stratusRunner.WarmUp()
	defer stratusRunner.CleanUp()
	if err != nil {
		fmt.Println("Could not warm up TTP: " + err.Error())
		return
	}

	fmt.Println("TTP is warm! Press enter to detonate it")
	fmt.Scanln()

	err = stratusRunner.Detonate()
	if err != nil {
		fmt.Println("Could not detonate TTP: " + err.Error())
	}
}
