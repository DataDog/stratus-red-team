package state

import (
	"github.com/datadog/stratus-red-team/internal/utils"
	"log"
	"os"
	"path/filepath"
)

var dir string

func init() {
	homeDirectory, _ := os.UserHomeDir()
	path := filepath.Join(homeDirectory, ".stratus-red-team")
	if !utils.FileExists(path) {
		log.Println("Creating " + path + " as it doesn't exist yet")
		err := os.Mkdir(path, 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}
	dir = path
}

func GetStateDirectory() string {
	return dir
}
