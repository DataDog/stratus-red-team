package state

import (
	"encoding/json"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"log"
	"os"
	"path/filepath"
)

const StratusStateDirectoryName = ".stratus-red-team"
const StratusStateTerraformOutputsFileName = ".terraform-outputs"
const StratusStateTechniqueStateFileName = ".state"
const StratusStateTerraformFileName = "main.tf"

type FileSystemStateManager struct {
	RootDirectory string
	Technique     *stratus.AttackTechnique
	FileSystem    FileSystem
}

type FileSystem interface {
	FileExists(string) bool
	CreateDirectory(string, os.FileMode) error
	RemoveDirectory(string) error
	WriteFile(string, []byte, os.FileMode) error
	ReadFile(string) ([]byte, error)
}

type LocalFileSystem struct{}

func (m *LocalFileSystem) FileExists(fileName string) bool {
	return utils.FileExists(fileName)
}

func (m *LocalFileSystem) CreateDirectory(dir string, mode os.FileMode) error {
	return os.Mkdir(dir, mode)
}

func (m *LocalFileSystem) RemoveDirectory(dir string) error {
	return os.RemoveAll(dir)
}

func (m *LocalFileSystem) WriteFile(file string, content []byte, mode os.FileMode) error {
	return os.WriteFile(file, content, mode)
}

func (m *LocalFileSystem) ReadFile(file string) ([]byte, error) {
	return os.ReadFile(file)
}

type StateManager interface {
	Initialize()
	GetRootDirectory() string
	ExtractTechnique() error
	CleanupTechnique() error
	GetTerraformOutputs() (map[string]string, error)
	WriteTerraformOutputs(outputs map[string]string) error
	GetTechniqueState() stratus.AttackTechniqueState
	SetTechniqueState(state stratus.AttackTechniqueState) error
}

func NewFileSystemStateManager(technique *stratus.AttackTechnique) *FileSystemStateManager {
	homeDirectory, _ := os.UserHomeDir()
	stateManager := FileSystemStateManager{
		RootDirectory: filepath.Join(homeDirectory, StratusStateDirectoryName),
		Technique:     technique,
		FileSystem:    &LocalFileSystem{},
	}
	stateManager.Initialize()
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
