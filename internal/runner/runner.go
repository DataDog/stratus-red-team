package runner

import (
	"errors"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
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
	return Runner{
		Technique:        technique,
		ShouldWarmUp:     warmup,
		ShouldCleanup:    cleanup,
		TerraformManager: NewTerraformManager(path.Join(stateManager.GetRootDirectory(), "terraform")),
		StateManager:     stateManager,
	}
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

func (m *Runner) WarmUp() (string, error) {
	terraformDir, err := m.extractTerraformFile()
	if err != nil {
		return "", errors.New("unable to extract Terraform file: " + err.Error())
	}
	m.TerraformDir = terraformDir

	// If we don't want to warm up the technique or if the technique has no pre-requisites, nothing to do
	if !m.ShouldWarmUp || m.Technique.PrerequisitesTerraformCode == nil {
		return terraformDir, nil
	}

	log.Println("Warming up " + m.Technique.Name)
	err = m.TerraformManager.TerraformInitAndApply(terraformDir)
	if err != nil {
		return "", errors.New("Unable to run terraform apply on pre-requisite: " + err.Error())
	}

	return terraformDir, nil
}

func (m *Runner) Detonate() error {
	terraformDir, err := m.WarmUp()
	if err != nil {
		return err
	}
	m.TerraformDir = terraformDir

	// Detonate
	err = m.Technique.Detonate(map[string]string{})
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
