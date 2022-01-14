package runner

import (
	"encoding/json"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
)

const StratusStateDirectoryName = ".stratus-red-team"

type StateManager struct {
	RootDirectory string
	Technique     *stratus.AttackTechnique
}

func NewStateManager(technique *stratus.AttackTechnique) *StateManager {
	homeDirectory, _ := os.UserHomeDir()
	stateManager := StateManager{
		RootDirectory: filepath.Join(homeDirectory, StratusStateDirectoryName),
		Technique:     technique,
	}
	stateManager.initialize()
	return &stateManager
}

func (m *StateManager) initialize() {
	if !utils.FileExists(m.RootDirectory) {
		log.Println("Creating " + m.RootDirectory + " as it doesn't exist yet")
		err := os.Mkdir(m.RootDirectory, 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}
}

func (m *StateManager) ExtractTechniqueTerraformFile() error {
	terraformDirectory := filepath.Join(m.RootDirectory, m.Technique.ID)
	terraformFile := filepath.Join(terraformDirectory, "main.tf")

	if utils.FileExists(terraformDirectory) {
		return nil
	}
	err := os.Mkdir(terraformDirectory, 0744)
	if err != nil {
		return err
	}
	return os.WriteFile(terraformFile, m.Technique.PrerequisitesTerraformCode, 0644)
}

func (m *StateManager) GetTechniqueOutputs() (map[string]string, error) {
	outputPath := path.Join(m.RootDirectory, m.Technique.ID, ".terraform-outputs")
	outputs := make(map[string]string)

	// If we have persisted Terraform outputs on disk, read them
	if utils.FileExists(outputPath) {
		outputString, err := ioutil.ReadFile(outputPath)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(outputString, &outputs)
		if err != nil {
			return nil, err
		}
	}
	return outputs, nil
}

func (m *StateManager) WriteTerraformOutputs(outputs map[string]string) error {
	outputPath := path.Join(m.RootDirectory, m.Technique.ID, ".terraform-outputs")
	outputString, err := json.Marshal(outputs)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outputPath, outputString, 0744)
}

func (m *StateManager) GetTechniqueState() AttackTechniqueState {
	rawState, _ := ioutil.ReadFile(filepath.Join(m.RootDirectory, m.Technique.ID, ".state"))
	return AttackTechniqueState(rawState)
}

func (m *StateManager) SetTechniqueState(state AttackTechniqueState) error {
	file := filepath.Join(m.RootDirectory, m.Technique.ID, ".state")
	return ioutil.WriteFile(file, []byte(state), 0744)
}

func (m *StateManager) GetRootDirectory() string {
	return m.RootDirectory
}
