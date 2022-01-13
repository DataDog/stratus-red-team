package runner

import (
	"github.com/datadog/stratus-red-team/internal/utils"
	"log"
	"os"
	"path/filepath"
)

const StratusStateDirectoryName = ".stratus-red-team"

type StateManager struct {
	RootDirectory string
}

func NewStateManager() *StateManager {
	homeDirectory, _ := os.UserHomeDir()
	stateManager := StateManager{
		RootDirectory: filepath.Join(homeDirectory, StratusStateDirectoryName),
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

func (m *StateManager) GetRootDirectory() string {
	return m.RootDirectory
}
