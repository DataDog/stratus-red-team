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
	TechniqueState   AttackTechniqueState
	TerraformDir     string
	ShouldCleanup    bool
	ShouldWarmUp     bool
	TerraformManager *TerraformManager
	StateManager     *StateManager
}

type AttackTechniqueState string

const (
	AttackTechniqueCold      = "COLD"
	AttackTechniqueWarm      = "WARM"
	AttackTechniqueDetonated = "DETONATED"
)

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
	m.TerraformDir = filepath.Join(m.StateManager.GetRootDirectory(), m.Technique.Name)
	rawState, _ := ioutil.ReadFile(filepath.Join(m.TerraformDir, ".state"))
	m.TechniqueState = AttackTechniqueState(rawState)
	if m.TechniqueState == "" {
		m.TechniqueState = AttackTechniqueCold
	}
}

// Utility function to extract the Terraform file of a technique
// to the filesystem
func (m *Runner) extractTerraformFile() error {
	if utils.FileExists(m.TerraformDir) {
		return nil
	}
	err := os.Mkdir(m.TerraformDir, 0744)
	if err != nil {
		return err
	}

	terraformFilePath := filepath.Join(m.TerraformDir, "main.tf")
	err = os.WriteFile(terraformFilePath, m.Technique.PrerequisitesTerraformCode, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (m *Runner) WarmUp() (string, map[string]string, error) {
	err := m.extractTerraformFile()
	if err != nil {
		return "", nil, errors.New("unable to extract Terraform file: " + err.Error())
	}
	outputPath := path.Join(m.TerraformDir, ".terraform-outputs")

	// No pre-requisites to spin-up
	if m.Technique.PrerequisitesTerraformCode == nil {
		return m.TerraformDir, nil, nil
	}

	// We don't want to warm up the technique
	if !m.ShouldWarmUp {
		outputs := make(map[string]string)
		// If we have persisted Terraform outputs on disk, read them
		if utils.FileExists(outputPath) {
			outputString, _ := ioutil.ReadFile(outputPath)
			json.Unmarshal(outputString, &outputs)
		}
		return m.TerraformDir, outputs, nil
	}

	// Technique is already warm (TODO --force)?
	if m.TechniqueState == AttackTechniqueWarm {
		log.Println(m.Technique.Name + " is already warm!")
		return m.TerraformDir, nil, nil
	}

	if m.TechniqueState == AttackTechniqueDetonated {
		log.Println(m.Technique.Name + " has not been cleaned up, not warming up")
		return m.TerraformDir, nil, nil
	}

	log.Println("Warming up " + m.Technique.Name)
	outputs, err := m.TerraformManager.TerraformInitAndApply(m.TerraformDir)
	if err != nil {
		return "", nil, errors.New("Unable to run terraform apply on pre-requisite: " + err.Error())
	}

	// Persist outputs to disk
	outputString, _ := json.Marshal(outputs)
	ioutil.WriteFile(outputPath, outputString, 0744)
	m.setState(AttackTechniqueWarm)

	return m.TerraformDir, outputs, nil
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
	m.setState(AttackTechniqueDetonated)
	return nil
}

func (m *Runner) CleanUp() error {
	var techniqueCleanupErr error
	var prerequisitesCleanupErr error

	// Revert detonation
	if m.Technique.Cleanup != nil {
		techniqueCleanupErr = m.Technique.Cleanup()
	}

	// Nuke pre-requisites
	if m.Technique.PrerequisitesTerraformCode != nil {
		log.Println("Cleaning up with terraform destroy")
		prerequisitesCleanupErr = m.TerraformManager.TerraformDestroy(m.TerraformDir)
	}

	// Remove terraform directory
	err := os.RemoveAll(m.TerraformDir)
	if err != nil {
		log.Println("Unable to remove technique directory " + m.TerraformDir + ": " + err.Error())
	}

	if techniqueCleanupErr == nil && prerequisitesCleanupErr == nil {
		m.setState(AttackTechniqueCold)
		return nil
	} else if techniqueCleanupErr != nil {
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

func (m *Runner) GetState() AttackTechniqueState {
	return m.TechniqueState
}

func (m *Runner) setState(state AttackTechniqueState) {
	file := filepath.Join(m.TerraformDir, ".state")
	ioutil.WriteFile(file, []byte(state), 0744)
	m.TechniqueState = state
}
