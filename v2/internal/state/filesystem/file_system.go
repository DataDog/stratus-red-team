package filesystem

import (
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"os"
)

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
