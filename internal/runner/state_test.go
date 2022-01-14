package runner

import (
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"os"
	"testing"
)

func noop(terraformOutputs map[string]string) error {
	return nil
}

type MockFileSystem struct {
	mock.Mock
}

func (m *MockFileSystem) FileExists(path string) bool {
	args := m.Called(path)
	return args.Bool(0)
}
func (m *MockFileSystem) CreateDirectory(path string, mode os.FileMode) error {
	args := m.Called(path, mode)
	return args.Error(0)
}
func (m *MockFileSystem) WriteFile(path string, content []byte, mode os.FileMode) error {
	args := m.Called(path, content, mode)
	return args.Error(0)
}
func (m *MockFileSystem) ReadFile(path string) ([]byte, error) {
	args := m.Called(path)
	return []byte(args.String(0)), args.Error(1)
}

func TestStateManagerCreatesRootDirectoryIfNotExists(t *testing.T) {
	fsMock := new(MockFileSystem)

	fsMock.On("FileExists", mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team"
	})).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)

	statemanager := StateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "foo", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.initialize()
	fsMock.AssertCalled(t, "CreateDirectory", "/root/.stratus-red-team", mock.Anything)
}

func TestStateManagerDoesTryToCreateRootDirectoryIfExists(t *testing.T) {
	fsMock := new(MockFileSystem)

	fsMock.On("FileExists", mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team"
	})).Return(true)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)

	statemanager := StateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "foo", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.initialize()
	fsMock.AssertNotCalled(t, "CreateDirectory", mock.Anything, mock.Anything)
}

func TestStateManagerExtractsTechniqueTerraformFile(t *testing.T) {
	fsMock := new(MockFileSystem)
	fsMock.On("FileExists", mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team"
	})).Return(true)
	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	statemanager := StateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", PrerequisitesTerraformCode: []byte("terraform"), Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.initialize()
	err := statemanager.ExtractTechniqueTerraformFile()

	assert.Nil(t, err)

	fsMock.AssertCalled(t,
		"CreateDirectory",
		"/root/.stratus-red-team/my-technique",
		mock.Anything,
	)

	fsMock.AssertCalled(t,
		"WriteFile",
		"/root/.stratus-red-team/my-technique/main.tf",
		[]byte("terraform"),
		mock.Anything,
	)
}
