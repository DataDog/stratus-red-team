package state

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"

	"testing"

	"github.com/datadog/stratus-red-team/v2/internal/state/mocks"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func noop(map[string]string, stratus.CloudProviders) error {
	return nil
}

func TestStateManagerCreatesRootDirectoryIfNotExists(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)

	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "foo", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()
	fsMock.AssertCalled(t, "CreateDirectory", "/root/.stratus-red-team", mock.Anything)
	// The working directory is created lazily, on the first write. Creating it here would leave
	// an empty directory behind for every command that turns out to have nothing to do.
	fsMock.AssertNotCalled(t, "CreateDirectory", "/root/.stratus-red-team/foo", mock.Anything)

	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	err := statemanager.SetTechniqueState(stratus.AttackTechniqueStatusWarm)

	assert.Nil(t, err)
	fsMock.AssertCalled(t, "CreateDirectory", "/root/.stratus-red-team/foo", mock.Anything)
}

func TestStateManagerExtractsTechniqueTerraformFiles(t *testing.T) {
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
	err := statemanager.ExtractTechnique()

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

	// config.tf and correlation.tf are just as required: a technique referencing var.correlation
	// fails at apply time without them, which is the regression #909 fixed for the S3 backend.
	fsMock.AssertCalled(t, "WriteFile",
		"/root/.stratus-red-team/my-technique/config.tf", mock.Anything, mock.Anything)
	fsMock.AssertCalled(t, "WriteFile",
		"/root/.stratus-red-team/my-technique/correlation.tf", mock.Anything, mock.Anything)
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
	outputs, err := statemanager.GetTerraformOutputs()

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

func TestStateManagerSetsTechniqueState(t *testing.T) {
	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory: "/root/.stratus-red-team",
		Technique:     &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:    fsMock,
	}
	statemanager.Initialize()

	err := statemanager.SetTechniqueState(stratus.AttackTechniqueStatusDetonated)
	assert.Nil(t, err)
	fsMock.AssertCalled(t,
		"WriteFile",
		"/root/.stratus-red-team/my-technique/.state",
		[]byte(stratus.AttackTechniqueStatusDetonated),
		mock.Anything,
	)
}

// The subdirectory is free-form and usually comes from an environment variable, so it must
// never be able to escape the technique directory or shadow one of the flat artifacts.
func TestSanitizeExecutionSubdirectory(t *testing.T) {
	scenario := []struct {
		Input    string
		Expected string
	}{
		{Input: "aabcdefa-1234-5678-9012-abcdef012345", Expected: "aabcdefa-1234-5678-9012-abcdef012345"},
		{Input: "sandbox1", Expected: "sandbox1"},
		{Input: "", Expected: ""},
		{Input: "..", Expected: ""},
		{Input: "../../etc", Expected: ""},
		{Input: "foo/bar", Expected: ""},
		{Input: `foo\bar`, Expected: ""},
		{Input: "/absolute", Expected: ""},
		{Input: ".terraform", Expected: ""},
		{Input: ".state", Expected: ""},
	}

	for i := range scenario {
		assert.Equal(t, scenario[i].Expected, sanitizeExecutionSubdirectory(scenario[i].Input), "input %q", scenario[i].Input)
	}
}

// Terraform fails an apply when an object value carries an attribute its variable does not
// declare, so every field we marshal must exist in correlation.tf.
func TestMarshalCorrelationMatchesTerraformVariable(t *testing.T) {
	var attributes map[string]string
	err := json.Unmarshal([]byte(MarshalCorrelation(uuid.New())), &attributes)
	assert.Nil(t, err)
	assert.NotEmpty(t, attributes)

	for name := range attributes {
		declaration := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*=`)
		assert.Regexp(t, declaration, string(sharedCorrelationVariable),
			"attribute %q must be declared in correlation.tf", name)
	}
}

func flatVariablesWithCorrelationID(id uuid.UUID) []byte {
	raw, _ := json.Marshal(map[string]string{TerraformCorrelationVarName: MarshalCorrelation(id)})
	return raw
}

// Adopting the flat state only on an exact correlation-ID match is what makes the migration safe:
// two executions can never claim the same state, and state predating the persisted ID is skipped.
func TestFlatStateBelongsToExecution(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	otherID := uuid.MustParse("ffffffff-1234-5678-9012-abcdef012345")

	scenario := []struct {
		Name                  string
		ExecutionSubdirectory string
		Variables             map[string]string
		Expected              bool
	}{
		{
			Name:                  "matching correlation id",
			ExecutionSubdirectory: executionID.String(),
			Variables:             map[string]string{TerraformCorrelationVarName: MarshalCorrelation(executionID)},
			Expected:              true,
		},
		{
			Name:                  "different correlation id",
			ExecutionSubdirectory: executionID.String(),
			Variables:             map[string]string{TerraformCorrelationVarName: MarshalCorrelation(otherID)},
			Expected:              false,
		},
		{
			// State written before Stratus v2.32.0 has no correlation id to match against.
			Name:                  "no correlation key at all",
			ExecutionSubdirectory: executionID.String(),
			Variables:             map[string]string{"config": "{}"},
			Expected:              false,
		},
		{
			Name:                  "no variables at all",
			ExecutionSubdirectory: executionID.String(),
			Variables:             map[string]string{},
			Expected:              false,
		},
		{
			Name:                  "unparseable correlation value",
			ExecutionSubdirectory: executionID.String(),
			Variables:             map[string]string{TerraformCorrelationVarName: "not-json"},
			Expected:              false,
		},
		{
			Name:                  "flat layout never migrates",
			ExecutionSubdirectory: "",
			Variables:             map[string]string{TerraformCorrelationVarName: MarshalCorrelation(executionID)},
			Expected:              false,
		},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			assert.Equal(t, scenario[i].Expected,
				flatStateBelongsToExecution(scenario[i].ExecutionSubdirectory, scenario[i].Variables))
		})
	}
}

func TestStateManagerMigratesFlatState(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	techniqueDirectory := "/root/.stratus-red-team/my-technique"
	workingDirectory := techniqueDirectory + "/" + executionID.String()

	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", techniqueDirectory+"/.terraform-variables").Return(true)
	// Absent, so the migration has not completed yet.
	fsMock.On("FileExists", workingDirectory+"/.state").Return(false)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", techniqueDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(executionID), nil)
	fsMock.On("ListDirectory", techniqueDirectory).Return([]string{
		".state", ".terraform-outputs", ".terraform-variables", ".terraform-initialized",
		".terraform", "main.tf", "terraform.tfstate", "other-execution",
	}, nil)
	fsMock.On("IsDirectory", techniqueDirectory+"/other-execution").Return(true)
	fsMock.On("IsDirectory", mock.Anything).Return(false)
	fsMock.On("Rename", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("RemoveAll", mock.Anything).Return(nil)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory:         "/root/.stratus-red-team",
		Technique:             &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:            fsMock,
		ExecutionSubdirectory: executionID.String(),
	}
	statemanager.migrateFlatState()

	// The load-bearing artifacts move into this execution's directory.
	for _, name := range []string{".terraform-outputs", ".terraform-variables", ".terraform", "terraform.tfstate", ".state"} {
		fsMock.AssertCalled(t, "Rename", techniqueDirectory+"/"+name, workingDirectory+"/"+name)
	}
	// The init marker is dropped, not moved, so Terraform re-initializes in the new directory.
	fsMock.AssertNotCalled(t, "Rename", techniqueDirectory+"/.terraform-initialized", mock.Anything)
	fsMock.AssertCalled(t, "RemoveAll", techniqueDirectory+"/.terraform-initialized")
	// Another execution's directory is never touched.
	fsMock.AssertNotCalled(t, "Rename", techniqueDirectory+"/other-execution", mock.Anything)

	// The state file is moved last: until it lands, the flat state stays authoritative.
	renames := []string{}
	for _, call := range fsMock.Calls {
		if call.Method == "Rename" {
			renames = append(renames, call.Arguments.String(0))
		}
	}
	require.NotEmpty(t, renames)
	assert.Equal(t, techniqueDirectory+"/.state", renames[len(renames)-1])
}

// A completed migration must not run again: the state file already sits in the destination.
func TestStateManagerDoesNotMigrateTwice(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	const techniqueDirectory = "/root/.stratus-red-team/my-technique"

	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", techniqueDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(executionID), nil)

	statemanager := FileSystemStateManager{
		RootDirectory:         "/root/.stratus-red-team",
		Technique:             &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:            fsMock,
		ExecutionSubdirectory: executionID.String(),
	}
	statemanager.migrateFlatState()

	fsMock.AssertNotCalled(t, "Rename", mock.Anything, mock.Anything)
}

// An interrupted migration is resumed rather than restarted, and a source another process already
// moved is not an error.
func TestStateManagerResumesInterruptedMigration(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	const techniqueDirectory = "/root/.stratus-red-team/my-technique"
	workingDirectory := techniqueDirectory + "/" + executionID.String()

	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", workingDirectory+"/.state").Return(false)
	// Already moved by the interrupted attempt.
	fsMock.On("FileExists", techniqueDirectory+"/terraform.tfstate").Return(false)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", techniqueDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(executionID), nil)
	fsMock.On("ListDirectory", techniqueDirectory).
		Return([]string{".state", ".terraform-variables", "terraform.tfstate"}, nil)
	fsMock.On("IsDirectory", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("Rename", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory:         "/root/.stratus-red-team",
		Technique:             &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:            fsMock,
		ExecutionSubdirectory: executionID.String(),
	}
	statemanager.migrateFlatState()

	fsMock.AssertCalled(t, "Rename", techniqueDirectory+"/.terraform-variables", workingDirectory+"/.terraform-variables")
	fsMock.AssertCalled(t, "Rename", techniqueDirectory+"/.state", workingDirectory+"/.state")
	fsMock.AssertNotCalled(t, "Rename", techniqueDirectory+"/terraform.tfstate", mock.Anything)
}

// A failed removal must leave .state behind: reporting COLD while cloud resources are live is
// worse than failing loudly.
func TestCleanupKeepsStateFileWhenRemovalFails(t *testing.T) {
	const techniqueDirectory = "/root/.stratus-red-team/my-technique"
	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ListDirectory", techniqueDirectory).Return([]string{".state", "terraform.tfstate", "main.tf"}, nil)
	fsMock.On("IsDirectory", mock.Anything).Return(false)
	fsMock.On("RemoveAll", techniqueDirectory+"/terraform.tfstate").Return(errors.New("device busy"))
	fsMock.On("RemoveAll", mock.Anything).Return(nil)
	fsMock.On("RemoveEmptyDirectory", mock.Anything).Return(nil)

	err := removeWorkingDirectory(fsMock, techniqueDirectory, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "device busy")
	fsMock.AssertNotCalled(t, "RemoveAll", techniqueDirectory+"/.state")
	fsMock.AssertNotCalled(t, "RemoveEmptyDirectory", mock.Anything)
}

// An interrupted migration must not plant the completion marker, or the execution would look
// migrated while its Terraform state is still in the flat layout.
func TestMigrationAbortsBeforeMovingTheStateFile(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	const techniqueDirectory = "/root/.stratus-red-team/my-technique"
	workingDirectory := techniqueDirectory + "/" + executionID.String()

	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", workingDirectory+"/.state").Return(false)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", techniqueDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(executionID), nil)
	fsMock.On("ListDirectory", techniqueDirectory).
		Return([]string{".state", ".terraform-variables", "terraform.tfstate"}, nil)
	fsMock.On("IsDirectory", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("Rename", techniqueDirectory+"/terraform.tfstate", mock.Anything).Return(errors.New("EXDEV"))
	fsMock.On("Rename", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory:         "/root/.stratus-red-team",
		Technique:             &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:            fsMock,
		ExecutionSubdirectory: executionID.String(),
	}
	statemanager.migrateFlatState()

	fsMock.AssertNotCalled(t, "Rename", techniqueDirectory+"/.state", mock.Anything)
}

// The variables file is both the ownership proof and one of the things being moved, so a retry
// after it has already moved must still recognise the state as its own.
func TestMigrationResumesAfterTheOwnershipProofMoved(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	const techniqueDirectory = "/root/.stratus-red-team/my-technique"
	workingDirectory := techniqueDirectory + "/" + executionID.String()

	fsMock := new(mocks.FileSystemMock)
	fsMock.On("FileExists", workingDirectory+"/.state").Return(false)
	fsMock.On("FileExists", techniqueDirectory+"/.terraform-variables").Return(false)
	fsMock.On("FileExists", mock.Anything).Return(true)
	// Already moved by the interrupted attempt; only the working copy can prove ownership now.
	fsMock.On("ReadFile", workingDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(executionID), nil)
	fsMock.On("ListDirectory", techniqueDirectory).Return([]string{".state", "terraform.tfstate"}, nil)
	fsMock.On("IsDirectory", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("Rename", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory:         "/root/.stratus-red-team",
		Technique:             &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:            fsMock,
		ExecutionSubdirectory: executionID.String(),
	}
	statemanager.migrateFlatState()

	fsMock.AssertCalled(t, "Rename", techniqueDirectory+"/terraform.tfstate", workingDirectory+"/terraform.tfstate")
	fsMock.AssertCalled(t, "Rename", techniqueDirectory+"/.state", workingDirectory+"/.state")
}

// Cleaning up one execution must leave the others untouched. This is the whole premise of the
// change, so it is asserted against the real filesystem rather than through mock call inspection.
func TestConcurrentExecutionsDoNotClobberEachOther(t *testing.T) {
	root := t.TempDir()
	technique := &stratus.AttackTechnique{ID: "aws.test.concurrent", Detonate: noop}
	newManager := func(subdirectory string) *FileSystemStateManager {
		manager := &FileSystemStateManager{
			RootDirectory:         root,
			Technique:             technique,
			FileSystem:            &LocalFileSystem{},
			ExecutionSubdirectory: subdirectory,
		}
		manager.Initialize()
		return manager
	}

	first, second, flat := newManager("execution-a"), newManager("execution-b"), newManager("")
	require.NoError(t, first.SetTechniqueState(stratus.AttackTechniqueStatusWarm))
	require.NoError(t, second.SetTechniqueState(stratus.AttackTechniqueStatusDetonated))
	require.NoError(t, flat.SetTechniqueState(stratus.AttackTechniqueStatusWarm))

	require.NoError(t, first.CleanupTechnique())
	assert.Equal(t, stratus.AttackTechniqueState(stratus.AttackTechniqueStatusDetonated), second.GetTechniqueState())
	assert.Equal(t, stratus.AttackTechniqueState(stratus.AttackTechniqueStatusWarm), flat.GetTechniqueState())

	// A flat cleanup running alongside an isolated execution must spare it.
	require.NoError(t, flat.CleanupTechnique())
	assert.Equal(t, stratus.AttackTechniqueState(stratus.AttackTechniqueStatusDetonated), second.GetTechniqueState())
	assert.DirExists(t, filepath.Join(root, technique.ID, "execution-b"))

	// Once the last execution goes, so does the technique directory.
	require.NoError(t, second.CleanupTechnique())
	assert.NoDirExists(t, filepath.Join(root, technique.ID))

	// A flat execution with no siblings takes the technique directory with it too.
	lone := newManager("")
	require.NoError(t, lone.SetTechniqueState(stratus.AttackTechniqueStatusWarm))
	require.NoError(t, lone.CleanupTechnique())
	assert.NoDirExists(t, filepath.Join(root, technique.ID))
}

// A flat proof that is present but belongs to someone else must win over a stale working copy
// left by an interrupted migration; otherwise this execution adopts the other one's state.
func TestMigrationDoesNotAdoptFlatStateOwnedBySomeoneElse(t *testing.T) {
	executionID := uuid.MustParse("aabcdefa-1234-5678-9012-abcdef012345")
	otherID := uuid.MustParse("ffffffff-1234-5678-9012-abcdef012345")
	const techniqueDirectory = "/root/.stratus-red-team/my-technique"
	workingDirectory := techniqueDirectory + "/" + executionID.String()

	fsMock := new(mocks.FileSystemMock)
	// Absent, so the completion-marker guard cannot short-circuit: the ownership check is what
	// has to stop this migration.
	fsMock.On("FileExists", workingDirectory+"/.state").Return(false)
	fsMock.On("FileExists", mock.Anything).Return(true)
	// A later flat run rewrote the proof, so the flat state is now the other execution's.
	fsMock.On("ReadFile", techniqueDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(otherID), nil)
	// Left behind by our own interrupted migration.
	fsMock.On("ReadFile", workingDirectory+"/.terraform-variables").
		Return(flatVariablesWithCorrelationID(executionID), nil)
	fsMock.On("ListDirectory", mock.Anything).Return([]string{".state", "terraform.tfstate"}, nil)
	fsMock.On("IsDirectory", mock.Anything).Return(false)
	fsMock.On("CreateDirectory", mock.Anything, mock.Anything).Return(nil)
	fsMock.On("Rename", mock.Anything, mock.Anything).Return(nil)

	statemanager := FileSystemStateManager{
		RootDirectory:         "/root/.stratus-red-team",
		Technique:             &stratus.AttackTechnique{ID: "my-technique", Detonate: noop},
		FileSystem:            fsMock,
		ExecutionSubdirectory: executionID.String(),
	}
	statemanager.migrateFlatState()

	fsMock.AssertNotCalled(t, "Rename", mock.Anything, mock.Anything)
	fsMock.AssertNotCalled(t, "ListDirectory", mock.Anything)
}
