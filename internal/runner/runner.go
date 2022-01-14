package runner

import (
	"errors"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"log"
	"os"
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
	ShouldForce      bool
	TerraformManager *TerraformManager
	StateManager     *StateManager
}

type AttackTechniqueState string

const (
	AttackTechniqueCold      = "COLD"
	AttackTechniqueWarm      = "WARM"
	AttackTechniqueDetonated = "DETONATED"
)

func NewRunner(technique *stratus.AttackTechnique, warmup bool, cleanup bool, force bool) Runner {
	stateManager := NewStateManager(technique)
	runner := Runner{
		Technique:        technique,
		ShouldWarmUp:     warmup,
		ShouldCleanup:    cleanup,
		ShouldForce:      force,
		TerraformManager: NewTerraformManager(filepath.Join(stateManager.GetRootDirectory(), "terraform")),
		StateManager:     stateManager,
	}
	runner.initialize()

	return runner
}

func (m *Runner) initialize() {
	m.ValidatePlatformRequirements()
	m.TerraformDir = filepath.Join(m.StateManager.GetRootDirectory(), m.Technique.ID)
	m.TechniqueState = m.StateManager.GetTechniqueState()
	if m.TechniqueState == "" {
		m.TechniqueState = AttackTechniqueCold
	}
}

func (m *Runner) WarmUp() (string, map[string]string, error) {
	err := m.StateManager.ExtractTechniqueTerraformFile()
	if err != nil {
		return "", nil, errors.New("unable to extract Terraform file: " + err.Error())
	}

	// No pre-requisites to spin-up
	if m.Technique.PrerequisitesTerraformCode == nil {
		return m.TerraformDir, nil, nil
	}

	// We don't want to warm up the technique
	var willWarmUp = m.ShouldWarmUp

	// Technique is already warm
	if m.TechniqueState == AttackTechniqueWarm && !m.ShouldForce {
		log.Println("Not warming up - " + m.Technique.ID + " is already warm. Use --force to force")
		willWarmUp = false
	}

	if m.TechniqueState == AttackTechniqueDetonated {
		log.Println(m.Technique.ID + " has been detonated but not cleaned up, not warming up as it should be warm already.")
		willWarmUp = false
	}

	if !willWarmUp {
		outputs, err := m.StateManager.GetTechniqueOutputs()
		return m.TerraformDir, outputs, err
	}

	log.Println("Warming up " + m.Technique.ID)
	outputs, err := m.TerraformManager.TerraformInitAndApply(m.TerraformDir)
	if err != nil {
		return "", nil, errors.New("Unable to run terraform apply on pre-requisite: " + err.Error())
	}

	// Persist outputs to disk
	m.StateManager.WriteTerraformOutputs(outputs)
	m.setState(AttackTechniqueWarm)

	if display, ok := outputs["display"]; ok {
		log.Println(display)
	}
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
		return errors.New("Error while detonating attack technique " + m.Technique.ID + ": " + err.Error())
	}
	m.setState(AttackTechniqueDetonated)
	return nil
}

func (m *Runner) CleanUp() error {
	var techniqueCleanupErr error
	var prerequisitesCleanupErr error

	// Has the technique already been cleaned up?
	if m.TechniqueState == AttackTechniqueCold && !m.ShouldForce {
		return errors.New(m.Technique.ID + " is already COLD and should be clean, use --force to force cleanup")
	}

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
	m.StateManager.SetTechniqueState(state)
	m.TechniqueState = state
}
