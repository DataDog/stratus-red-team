package state

import (
	"github.com/datadog/stratus-red-team/internal/state/mocks"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func noop(map[string]string) error {
	return nil
}

func TestStateManagerCreatesRootDirectoryIfNotExists(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)

	fsMock.On("FileExists", mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team"
	})).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "foo", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()
	fsMock.AssertCalled(t, "CreateDirectory", "/root/.stratus-red-team", mock.Anything)
}

func TestStateManagerDoesTryToCreateRootDirectoryIfExists(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)

	fsMock.On("FileExists", mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team"
	})).Return(true)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "foo", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()
	fsMock.AssertNotCalled(t, "CreateDirectory", mock.Anything, mock.Anything)
}

func TestStateManagerExtractsTechniqueTerraformFile(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team"
	})).Return(true)
	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", PrerequisitesTerraformCode: []byte("terraform"), Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()
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

func TestStateManagerRetrievesTechniqueOutputs(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)
	fileMatcher := mock.MatchedBy(func(file string) bool {
		return file == "/root/.stratus-red-team/my-technique/.terraform-outputs"
	})
	fsMock.On("FileExists", fileMatcher).Return(true)
	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("ReadFile", fileMatcher).Return([]byte("{\"foo\": \"bar\"}"), nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()
	outputs, err := statemanager.GetTechniqueOutputs()

	assert.Nil(t, err)
	assert.Len(t, outputs, 1)
	assert.Equal(t, "bar", outputs["foo"])
}

func TestStateManagerWritesTechniqueOutputs(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)
	outputFile := "/root/.stratus-red-team/my-technique/.terraform-outputs"
	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()
	err := statemanager.WriteTerraformOutputs(map[string]string{"bar": "foo"})

	assert.Nil(t, err)
	fsMock.AssertCalled(t, "WriteFile", outputFile, []byte("{\"bar\":\"foo\"}"), mock.Anything)
}

func TestStateManagerReadsTechniqueState(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", "/root/.stratus-red-team/my-technique/.state").Return([]byte(stratus.AttackTechniqueCold), nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()

	state := statemanager.GetTechniqueState()
	assert.Equal(t, stratus.AttackTechniqueState(stratus.AttackTechniqueCold), state)

}

func TestStateManagerSetsTechniqueState(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()

	err := statemanager.SetTechniqueState(stratus.AttackTechniqueDetonated)
	assert.Nil(t, err)
	fsMock.AssertCalled(t,
		"WriteFile",
		"/root/.stratus-red-team/my-technique/.state",
		[]byte(stratus.AttackTechniqueDetonated),
		mock.Anything,
	)

}

// characteristics:
// root dir exists?
// technique dir exists?
// output file?
