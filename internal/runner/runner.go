package runner

import (
	"encoding/json"
	"errors"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
)

type RunOptions struct {
	Cleanup bool
	Warmup  bool
}

type Runner struct {
	Technique        *stratus.AttackTechnique
	TerraformDir     string
	ShouldCleanup    bool
	ShouldWarmUp     bool
	TerraformManager *TerraformManager
	StateManager     *StateManager
}

func NewRunner(technique *stratus.AttackTechnique, warmup bool, cleanup bool) Runner {
	stateManager := NewStateManager()
	runner := Runner{
		Technique:        technique,
		ShouldWarmUp:     warmup,
		ShouldCleanup:    cleanup,
		TerraformManager: NewTerraformManager(path.Join(stateManager.GetRootDirectory(), "terraform")),
		StateManager:     stateManager,
	}
	runner.initialize()

	return runner
}

func (m *Runner) initialize() {
	m.ValidatePlatformRequirements()
}

// Utility function to extract the Terraform file of a technique
// to the filesystem
func (m *Runner) extractTerraformFile() (string, error) {
	dir := m.StateManager.GetRootDirectory()
	terraformDir := filepath.Join(dir, m.Technique.Name)
	terraformFilePath := filepath.Join(terraformDir, "main.tf")
	if utils.FileExists(terraformDir) {
		return terraformDir, nil
	}
	err := os.Mkdir(terraformDir, 0744)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(terraformFilePath, m.Technique.PrerequisitesTerraformCode, 0644)
	if err != nil {
		return "", err
	}

	return terraformDir, nil
}

func (m *Runner) WarmUp() (string, map[string]string, error) {
	terraformDir, err := m.extractTerraformFile()
	if err != nil {
		return "", nil, errors.New("unable to extract Terraform file: " + err.Error())
	}
	m.TerraformDir = terraformDir
	outputPath := path.Join(terraformDir, ".terraform-outputs")

	// No pre-requisites to spin-up
	if m.Technique.PrerequisitesTerraformCode == nil {
		return terraformDir, nil, nil
	}

	// We don't want to warm up the technique
	if !m.ShouldWarmUp {
		outputs := make(map[string]string)
		if utils.FileExists(outputPath) {
			outputString, _ := ioutil.ReadFile(outputPath)
			json.Unmarshal(outputString, &outputs)
		}
		return terraformDir, outputs, nil
	}

	log.Println("Warming up " + m.Technique.Name)
	outputs, err := m.TerraformManager.TerraformInitAndApply(terraformDir)
	if err != nil {
		return "", nil, errors.New("Unable to run terraform apply on pre-requisite: " + err.Error())
	}

	// Persist outputs to disk
	outputString, _ := json.Marshal(outputs)
	ioutil.WriteFile(outputPath, outputString, 0744)

	return terraformDir, outputs, nil
}

func (m *Runner) Detonate() error {
	terraformDir, outputs, err := m.WarmUp()
	if err != nil {
		return err
	}
	m.TerraformDir = terraformDir

	// Detonate
	err = m.Technique.Detonate(outputs)
	if m.ShouldCleanup {
		defer func() {
			err := m.CleanUp()
			if err != nil {
				log.Println("unable to clean up pre-requisites: " + err.Error())
			}
		}()
	}
	if err != nil {
		return errors.New("Error while detonating attack technique " + m.Technique.Name + ": " + err.Error())
	}

	return nil
}

func (m *Runner) CleanUp() error {
	var techniqueCleanupErr error
	var prerequisitesCleanupErr error
	if m.Technique.Cleanup != nil {
		techniqueCleanupErr = m.Technique.Cleanup()
	}
	if m.Technique.PrerequisitesTerraformCode != nil {
		log.Println("Cleaning up with terraform destroy")
		prerequisitesCleanupErr = m.TerraformManager.TerraformDestroy(m.TerraformDir)
	}

	if techniqueCleanupErr != nil {
		return techniqueCleanupErr
	} else {
		return prerequisitesCleanupErr
	}
}

func (m *Runner) ValidatePlatformRequirements() {
	switch m.Technique.Platform {
	case stratus.AWS:
		if !providers.AWS().IsAuthenticatedAgainstAWS() {
			log.Fatal("You are not authenticated against AWS, or you have not set your region.")
		}
	}
}
