package state

import (
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/config"
	"github.com/google/uuid"
)

// sharedCorrelationVariable is the shared Terraform variable "correlation",
// injected alongside technique main.tf files at warmup time. Techniques can
// use var.correlation.id to embed the correlation ID in resource names.
//
//go:embed correlation.tf
var sharedCorrelationVariable []byte

// TerraformCorrelationVarName is the key under which MarshalCorrelation's output
// is passed to Terraform; matches the variable declared in correlation.tf.
const TerraformCorrelationVarName = "correlation"

// TerraformCorrelation mirrors the schema of the "correlation" Terraform variable
// declared in correlation.tf. Keep the JSON tags in sync with that file: Terraform rejects an
// object value carrying an attribute the variable does not declare.
type TerraformCorrelation struct {
	ID    string `json:"id"`
	Short string `json:"short"`
}

// MarshalCorrelation returns the JSON-encoded value Terraform expects for var.correlation.
func MarshalCorrelation(id uuid.UUID) string {
	correlation := TerraformCorrelation{ID: id.String()}
	correlation.Short = stratus.CorrelationShortID(id)
	encoded, err := json.Marshal(correlation)
	if err != nil {
		// json.Marshal of a struct of string fields cannot fail.
		log.Error("unable to marshal correlation: " + err.Error())
		return "{}"
	}
	return string(encoded)
}

const StratusStateTerraformFileName = "main.tf"
const StratusStateTerraformInitializedFileName = ".terraform-initialized"

// Artifacts are the important files. If using the S3StateManager, they are saved to the remote bucket.
type stateArtifact struct {
	FileName string
	S3Key    string
}

var (
	techniqueStateArtifact     = stateArtifact{FileName: ".state", S3Key: "state"}
	terraformOutputsArtifact   = stateArtifact{FileName: ".terraform-outputs", S3Key: "outputs.json"}
	terraformVariablesArtifact = stateArtifact{FileName: ".terraform-variables", S3Key: "variables.json"}
	terraformStateArtifact     = stateArtifact{FileName: "terraform.tfstate", S3Key: "terraform.tfstate"}

	stateArtifacts = []stateArtifact{
		techniqueStateArtifact,
		terraformOutputsArtifact,
		terraformVariablesArtifact,
		terraformStateArtifact,
	}
)

// terraformCacheDirectoryName is the only directory Terraform creates inside a working
// directory; every other artifact it leaves behind is a file. That invariant is how we
// tell a concurrent execution's sub-directory apart from the flat layout's own files.
const terraformCacheDirectoryName = ".terraform"

// managerSettings holds the options shared by every state manager.
type managerSettings struct {
	executionSubdirectory string
	readOnly              bool
}

type ManagerOption func(*managerSettings)

// WithReadOnlyState skips the side effects of initialization: creating directories and migrating
// state from an older layout.
//
// Used for instance in commands that only report state, such as `stratus status`.
func WithReadOnlyState() ManagerOption {
	return func(s *managerSettings) { s.readOnly = true }
}

// WithExecutionSubdirectory isolates this execution's state under a sub-directory of the
// technique directory. An empty (or unusable) name keeps the historical flat layout.
func WithExecutionSubdirectory(name string) ManagerOption {
	return func(s *managerSettings) { s.executionSubdirectory = sanitizeExecutionSubdirectory(name) }
}

func buildManagerSettings(opts []ManagerOption) managerSettings {
	var settings managerSettings
	for _, opt := range opts {
		opt(&settings)
	}
	return settings
}

// sanitizeExecutionSubdirectory returns a name usable as a single path segment, or "" when
// it is not. The name is free-form and typically comes from an environment variable, so it
// must never be able to escape the technique directory or shadow a flat artifact (all of
// which start with a dot).
func sanitizeExecutionSubdirectory(name string) string {
	// IsLocal rejects absolute paths, traversals and Windows device names such as NUL.
	if !filepath.IsLocal(name) {
		return ""
	}
	// Stricter than IsLocal: a single segment, so the name cannot nest, and no leading dot, so it
	// cannot shadow a flat artifact or the .terraform directory used to tell them apart.
	if strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return ""
	}
	return name
}

// correlationIDFromVariables extracts the correlation ID persisted alongside a technique's
// Terraform variables. It returns "" for state written before Stratus persisted the ID
// (< v2.32.0), which is what makes such state ineligible for automatic migration.
func correlationIDFromVariables(variables map[string]string) string {
	raw, found := variables[TerraformCorrelationVarName]
	if !found {
		return ""
	}
	var correlation TerraformCorrelation
	if err := json.Unmarshal([]byte(raw), &correlation); err != nil {
		return ""
	}
	return correlation.ID
}

// [backward compatibility] flatStateBelongsToExecution reports whether the state in the flat layout
// is this execution's own, and may therefore be adopted into its sub-directory.
func flatStateBelongsToExecution(executionSubdirectory string, flatVariables map[string]string) bool {
	if executionSubdirectory == "" {
		return false
	}
	return correlationIDFromVariables(flatVariables) == executionSubdirectory
}

// [backward compatibility] isExecutionSubdirectory reports whether an entry of the technique
// directory belongs to another execution rather than to the flat layout.
func isExecutionSubdirectory(fileSystem FileSystem, techniqueDirectory string, name string) bool {
	if name == terraformCacheDirectoryName {
		return false
	}
	return fileSystem.IsDirectory(filepath.Join(techniqueDirectory, name))
}

type FileSystemStateManager struct {
	RootDirectory         string
	Technique             *stratus.AttackTechnique
	FileSystem            FileSystem
	ExecutionSubdirectory string // isolates concurrent executions of the same technique
	ReadOnly              bool   // suppresses directory creation and state migration during initialization
}

type FileSystem interface {
	CreateDirectory(string, os.FileMode) error
	FileExists(string) bool
	IsDirectory(string) bool
	ListDirectory(string) ([]string, error)
	ReadFile(string) ([]byte, error)
	RemoveAll(string) error
	RemoveEmptyDirectory(string) error // Must errors if not empty. Must not recurse.
	Rename(string, string) error
	WriteFile(string, []byte, os.FileMode) error
}

type LocalFileSystem struct{}

// CreateDirectory creates dir and any missing parents.
func (m *LocalFileSystem) CreateDirectory(dir string, mode os.FileMode) error {
	return os.MkdirAll(dir, mode)
}

func (m *LocalFileSystem) FileExists(fileName string) bool {
	return utils.FileExists(fileName)
}

func (m *LocalFileSystem) IsDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (m *LocalFileSystem) ListDirectory(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (m *LocalFileSystem) ReadFile(file string) ([]byte, error) {
	return os.ReadFile(file)
}
func (m *LocalFileSystem) RemoveAll(dir string) error {
	return os.RemoveAll(dir)
}

func (m *LocalFileSystem) RemoveEmptyDirectory(dir string) error {
	return os.Remove(dir)
}

func (m *LocalFileSystem) Rename(oldPath string, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func (m *LocalFileSystem) WriteFile(file string, content []byte, mode os.FileMode) error {
	return os.WriteFile(file, content, mode)
}

type StateManager interface {
	Initialize()
	GetRootDirectory() string
	GetWorkingDirectory() string
	ExtractTechnique() error
	CleanupTechnique() error
	GetTerraformOutputs() (map[string]string, error)
	WriteTerraformOutputs(outputs map[string]string) error
	GetTerraformVariables() (map[string]string, error)
	WriteTerraformVariables(variables map[string]string) error
	GetTechniqueState() stratus.AttackTechniqueState
	SetTechniqueState(state stratus.AttackTechniqueState) error
}

func NewFileSystemStateManager(technique *stratus.AttackTechnique, opts ...ManagerOption) *FileSystemStateManager {
	homeDirectory, _ := os.UserHomeDir()
	settings := buildManagerSettings(opts)
	stateManager := FileSystemStateManager{
		RootDirectory:         filepath.Join(homeDirectory, config.StratusBaseDirectoryName),
		Technique:             technique,
		FileSystem:            &LocalFileSystem{},
		ExecutionSubdirectory: settings.executionSubdirectory,
		ReadOnly:              settings.readOnly,
	}
	stateManager.Initialize()
	return &stateManager
}

func (m *FileSystemStateManager) Initialize() {
	if m.ReadOnly {
		return
	}

	if !m.FileSystem.FileExists(m.RootDirectory) {
		log.Println("Creating " + m.RootDirectory + " as it doesn't exist yet")
		err := m.FileSystem.CreateDirectory(m.RootDirectory, 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}

	m.migrateFlatState()
}

// ensureWorkingDirectory creates this execution's directory.
// Usually called right before something is written into it, as creating it up-front instead would
// leave an empty directory behind for every command that turns out to have nothing to do.
func (m *FileSystemStateManager) ensureWorkingDirectory() error {
	return m.FileSystem.CreateDirectory(m.getTechniqueStateDirectory(), 0744)
}

// [backward compatibility] migrateFlatState moves state left in the flat layout by a Stratus
// version that did not isolate executions, to avoid orphaning an in-flight execution on upgrade.
//
// It is idempotent and resumable.
//
// A failure is never fatal, the execution simply proceeds without the previous state, which is
// recoverable by running the command again without specifying a correlation ID.
func (m *FileSystemStateManager) migrateFlatState() {
	if m.ExecutionSubdirectory == "" {
		// The flat layout is already where this execution reads from.
		return
	}
	techniqueDirectory := m.getTechniqueDirectory()
	workingDirectory := m.getTechniqueStateDirectory()

	if m.FileSystem.FileExists(filepath.Join(workingDirectory, techniqueStateArtifact.FileName)) {
		return
	}
	if !m.flatStateIsOurs(techniqueDirectory, workingDirectory) {
		return
	}

	names, err := m.FileSystem.ListDirectory(techniqueDirectory)
	if err != nil {
		log.Warnf("unable to migrate the previous state of %s: %s", m.Technique.ID, err.Error())
		return
	}

	log.Infof("migrating the existing state of %s to %s", m.Technique.ID, workingDirectory)
	if err := m.ensureWorkingDirectory(); err != nil {
		log.Warnf("unable to migrate the previous state of %s: %s", m.Technique.ID, err.Error())
		return
	}
	deferred := ""
	for _, name := range names {
		switch {
		case isExecutionSubdirectory(m.FileSystem, techniqueDirectory, name):
			continue
		case name == StratusStateTerraformInitializedFileName:
			// Dropped rather than moved, so that Terraform re-initializes in its new directory.
			if err := m.FileSystem.RemoveAll(filepath.Join(techniqueDirectory, name)); err != nil {
				log.Warnf("unable to remove %s: %s", name, err.Error())
			}
		case name == techniqueStateArtifact.FileName:
			deferred = name
		default:
			if err := m.migrateEntry(techniqueDirectory, workingDirectory, name); err != nil {
				// Leave .state behind: the flat state stays authoritative and the next run retries.
				log.Warnf("unable to migrate the previous state of %s: %s", m.Technique.ID, err.Error())
				return
			}
		}
	}
	if deferred != "" {
		if err := m.migrateEntry(techniqueDirectory, workingDirectory, deferred); err != nil {
			log.Warnf("unable to migrate the previous state of %s: %s", m.Technique.ID, err.Error())
		}
	}
}

// flatStateIsOurs reports whether the flat state belongs to this execution.
func (m *FileSystemStateManager) flatStateIsOurs(techniqueDirectory string, workingDirectory string) bool {
	proof := filepath.Join(techniqueDirectory, terraformVariablesArtifact.FileName) // flat state variables file
	if !m.FileSystem.FileExists(proof) {
		// working directory variables file. We do check it in case a previous attempt moved some of
		// the flat state before it could finish.
		proof = filepath.Join(workingDirectory, terraformVariablesArtifact.FileName)
	}
	variables, err := m.readJSONMap(proof)
	return err == nil && flatStateBelongsToExecution(m.ExecutionSubdirectory, variables)
}

func (m *FileSystemStateManager) migrateEntry(sourceDirectory string, destinationDirectory string, name string) error {
	source := filepath.Join(sourceDirectory, name)
	// A source that vanished was already migrated by a concurrent run: converge instead of failing.
	if !m.FileSystem.FileExists(source) {
		return nil
	}
	return m.FileSystem.Rename(source, filepath.Join(destinationDirectory, name))
}

// writeSharedTerraformFiles writes the Terraform source files common to every
// state backend into dir. Backend-specific files (e.g. the S3 backend.tf) stay
// with the caller, keeping this the single source of truth for the shared
// scaffolding so every StateManager stays in sync.
func writeSharedTerraformFiles(fileSystem FileSystem, directory string, technique *stratus.AttackTechnique) error {
	files := []struct {
		name    string
		content []byte
	}{
		{StratusStateTerraformFileName, technique.PrerequisitesTerraformCode},
		{"config.tf", config.SharedTerraformConfigVariable},
		{"correlation.tf", sharedCorrelationVariable},
	}
	for _, file := range files {
		if err := fileSystem.WriteFile(filepath.Join(directory, file.name), file.content, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (m *FileSystemStateManager) ExtractTechnique() error {
	if err := m.ensureWorkingDirectory(); err != nil {
		return err
	}
	return writeSharedTerraformFiles(m.FileSystem, m.getTechniqueStateDirectory(), m.Technique)
}

func (m *FileSystemStateManager) CleanupTechnique() error {
	return removeWorkingDirectory(m.FileSystem, m.getTechniqueDirectory(), m.ExecutionSubdirectory)
}

// removeWorkingDirectory removes this execution's working directory.
//
// In the flat layout the working directory is the technique directory itself, which may also
// host concurrent executions' sub-directories, so we can't use a simple recursive remove.
func removeWorkingDirectory(fileSystem FileSystem, techniqueDirectory string, executionSubdirectory string) error {
	if executionSubdirectory != "" {
		if err := fileSystem.RemoveAll(filepath.Join(techniqueDirectory, executionSubdirectory)); err != nil {
			return err
		}
		// Try to remove the technique dir. If another execution is running, will rightfully fail
		_ = fileSystem.RemoveEmptyDirectory(techniqueDirectory)
		return nil
	}

	if !fileSystem.FileExists(techniqueDirectory) {
		return nil
	}
	names, err := fileSystem.ListDirectory(techniqueDirectory)
	if err != nil {
		return err
	}

	// Only ever remove entries that existed when we listed. Recursively removing the technique
	// directory instead would also take an execution created since, along with its Terraform state.
	var errs []error
	stateFilePresent := false
	for _, name := range names {
		if isExecutionSubdirectory(fileSystem, techniqueDirectory, name) {
			continue // don't remove concurrent executions
		}
		if name == techniqueStateArtifact.FileName { // skip state file, removed at the end
			stateFilePresent = true
			continue
		}
		if err := fileSystem.RemoveAll(filepath.Join(techniqueDirectory, name)); err != nil {
			errs = append(errs, err)
		}
	}
	// Removed last, and only once the rest is gone, so a partial cleanup still reports its real
	// state rather than looking COLD while resources are live.
	if stateFilePresent && len(errs) == 0 {
		if err := fileSystem.RemoveAll(filepath.Join(techniqueDirectory, techniqueStateArtifact.FileName)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	_ = fileSystem.RemoveEmptyDirectory(techniqueDirectory)
	return nil
}

func (m *FileSystemStateManager) GetTerraformOutputs() (map[string]string, error) {
	return m.readJSONMap(m.getOutputsStateFile())
}

// readJSONMap reads a persisted string map, returning an empty one when the file does not exist.
func (m *FileSystemStateManager) readJSONMap(path string) (map[string]string, error) {
	result := make(map[string]string)
	if !m.FileSystem.FileExists(path) {
		return result, nil
	}
	raw, err := m.FileSystem.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *FileSystemStateManager) WriteTerraformOutputs(outputs map[string]string) error {
	outputString, err := json.Marshal(outputs)
	if err != nil {
		return err
	}
	if err := m.ensureWorkingDirectory(); err != nil {
		return err
	}
	return m.FileSystem.WriteFile(m.getOutputsStateFile(), outputString, 0744)
}

func (m *FileSystemStateManager) GetTerraformVariables() (map[string]string, error) {
	return m.readJSONMap(m.getVariablesStateFile())
}

func (m *FileSystemStateManager) WriteTerraformVariables(variables map[string]string) error {
	variablesString, err := json.Marshal(variables)
	if err != nil {
		return err
	}
	if err := m.ensureWorkingDirectory(); err != nil {
		return err
	}
	return m.FileSystem.WriteFile(m.getVariablesStateFile(), variablesString, 0744)
}

func (m *FileSystemStateManager) GetTechniqueState() stratus.AttackTechniqueState {
	rawState, _ := m.FileSystem.ReadFile(m.getTechniqueStateFile())
	return stratus.AttackTechniqueState(rawState)
}

func (m *FileSystemStateManager) SetTechniqueState(state stratus.AttackTechniqueState) error {
	if err := m.ensureWorkingDirectory(); err != nil {
		return err
	}
	return m.FileSystem.WriteFile(m.getTechniqueStateFile(), []byte(state), 0744)
}

// getTechniqueDirectory is the directory shared by every execution of the technique. It is
// the working directory itself in the flat layout, and the parent of the per-execution
// directories otherwise.
func (m *FileSystemStateManager) getTechniqueDirectory() string {
	return filepath.Join(m.RootDirectory, m.Technique.ID)
}

func (m *FileSystemStateManager) getTechniqueStateDirectory() string {
	return filepath.Join(m.getTechniqueDirectory(), m.ExecutionSubdirectory)
}

func (m *FileSystemStateManager) getTechniqueStateFile() string {
	return filepath.Join(m.getTechniqueStateDirectory(), techniqueStateArtifact.FileName)
}

func (m *FileSystemStateManager) getOutputsStateFile() string {
	return filepath.Join(m.getTechniqueStateDirectory(), terraformOutputsArtifact.FileName)
}

func (m *FileSystemStateManager) getVariablesStateFile() string {
	return filepath.Join(m.getTechniqueStateDirectory(), terraformVariablesArtifact.FileName)
}

func (m *FileSystemStateManager) GetRootDirectory() string {
	return m.RootDirectory
}

func (m *FileSystemStateManager) GetWorkingDirectory() string {
	return m.getTechniqueStateDirectory()
}
