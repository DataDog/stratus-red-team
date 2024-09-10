package manager

import (
	"encoding/json"
	"github.com/datadog/stratus-red-team/v2/internal/state/datastore"
	"github.com/datadog/stratus-red-team/v2/internal/state/filesystem"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"log"
	"os"
	"path/filepath"
)

const StratusStateDirectoryName = ".stratus-red-team"
const StratusStateTerraformOutputsFileName = ".terraform-outputs"
const StratusStateTechniqueStateFileName = ".state"
const StratusStateTerraformFileName = "main.tf"

type StateManager interface {
	Initialize()
	GetRootDirectory() string
	ExtractTechnique() error
	CleanupTechnique() error
	GetTerraformOutputs() (map[string]string, error)
	GetDataStore() datastore.DataStore
	WriteTerraformOutputs(outputs map[string]string) error
	GetTechniqueState() stratus.AttackTechniqueState
	SetTechniqueState(state stratus.AttackTechniqueState) error
}

type FileSystemStateManager struct {
	RootDirectory string
	Technique     *stratus.AttackTechnique
	FileSystem    filesystem.FileSystem
	DataStore     datastore.FileSystemDataStore
}

func NewFileSystemStateManager(technique *stratus.AttackTechnique) *FileSystemStateManager {
	homeDirectory, _ := os.UserHomeDir()
	localFileSystem := filesystem.LocalFileSystem{}
	stratusStateDirectory := filepath.Join(homeDirectory, StratusStateDirectoryName)

	stateManager := FileSystemStateManager{
		RootDirectory: stratusStateDirectory,
		Technique:     technique,
		FileSystem:    &localFileSystem,
	}

	stateManager.Initialize()

	stateManager.DataStore = datastore.FileSystemDataStore{
		FileSystem:              &localFileSystem,
		TechniqueStateDirectory: stateManager.getTechniqueStateDirectory(),
	}
	err := stateManager.DataStore.Load()
	if err != nil {
		panic("unable to load data store: " + err.Error())
	}

	return &stateManager
}

func (m *FileSystemStateManager) Initialize() {
	if !m.FileSystem.FileExists(m.RootDirectory) {
		log.Println("Creating " + m.RootDirectory + " as it doesn't exist yet")
		err := m.FileSystem.CreateDirectory(m.RootDirectory, 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}

	if !m.FileSystem.FileExists(m.getTechniqueStateDirectory()) {
		err := m.FileSystem.CreateDirectory(m.getTechniqueStateDirectory(), 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}
}

func (m *FileSystemStateManager) ExtractTechnique() error {
	terraformDirectory := m.getTechniqueStateDirectory()
	terraformFile := filepath.Join(terraformDirectory, StratusStateTerraformFileName)

	return m.FileSystem.WriteFile(terraformFile, m.Technique.PrerequisitesTerraformCode, 0644)
}

func (m *FileSystemStateManager) CleanupTechnique() error {
	return m.FileSystem.RemoveDirectory(m.getTechniqueStateDirectory())
}

func (m *FileSystemStateManager) GetTerraformOutputs() (map[string]string, error) {
	outputPath := m.getOutputsStateFile()
	outputs := make(map[string]string)

	// If we have persisted Terraform outputs on disk, read them
	if m.FileSystem.FileExists(outputPath) {
		outputString, err := m.FileSystem.ReadFile(outputPath)
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

func (m *FileSystemStateManager) GetDataStore() datastore.DataStore {
	return &m.DataStore
}

func (m *FileSystemStateManager) WriteTerraformOutputs(outputs map[string]string) error {
	outputString, err := json.Marshal(outputs)
	if err != nil {
		return err
	}
	return m.FileSystem.WriteFile(m.getOutputsStateFile(), outputString, 0744)
}

func (m *FileSystemStateManager) GetTechniqueState() stratus.AttackTechniqueState {
	rawState, _ := m.FileSystem.ReadFile(m.getTechniqueStateFile())
	return stratus.AttackTechniqueState(rawState)
}

func (m *FileSystemStateManager) SetTechniqueState(state stratus.AttackTechniqueState) error {
	return m.FileSystem.WriteFile(m.getTechniqueStateFile(), []byte(state), 0744)
}

func (m *FileSystemStateManager) getTechniqueStateDirectory() string {
	return filepath.Join(m.RootDirectory, m.Technique.ID)
}

func (m *FileSystemStateManager) getTechniqueStateFile() string {
	return filepath.Join(m.RootDirectory, m.Technique.ID, StratusStateTechniqueStateFileName)
}

func (m *FileSystemStateManager) getOutputsStateFile() string {
	return filepath.Join(m.RootDirectory, m.Technique.ID, StratusStateTerraformOutputsFileName)
}

func (m *FileSystemStateManager) GetRootDirectory() string {
	return m.RootDirectory
}
