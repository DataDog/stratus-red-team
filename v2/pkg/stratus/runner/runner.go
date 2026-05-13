package runner

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/config"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"github.com/google/uuid"
)

// S3BackendConfig is re-exported for external consumers that cannot import
// internal/state directly.
type S3BackendConfig = state.S3BackendConfig

const StratusRunnerForce = true
const StratusRunnerNoForce = false

const EnvVarStratusRedTeamCorrelationId = "STRATUS_RED_TEAM_CORRELATION_ID"

// Deprecated: Use EnvVarStratusRedTeamCorrelationId instead.
const EnvVarStratusRedTeamDetonationId = "STRATUS_RED_TEAM_DETONATION_ID"

// Use an existing terraform binary path instead of letting the runner download it.
const EnvVarStratusTerraformBinaryPath = "STRATUS_TERRAFORM_BINARY_PATH"

// RunnerOption configures optional dependencies on a Runner.
// When no options are provided, the runner uses its default implementations
// (filesystem state, bundled Terraform, default cloud provider credentials).
type RunnerOption func(*runnerImpl)

// WithStateManager overrides the default filesystem-based state manager.
func WithStateManager(sm state.StateManager) RunnerOption {
	return func(r *runnerImpl) { r.StateManager = sm }
}

// WithTerraformManager overrides the default Terraform manager.
func WithTerraformManager(tm TerraformManager) RunnerOption {
	return func(r *runnerImpl) { r.TerraformManager = tm }
}

// WithProviderFactory overrides the default cloud provider factory.
func WithProviderFactory(pf stratus.CloudProviders) RunnerOption {
	return func(r *runnerImpl) { r.ProviderFactory = pf }
}

// WithConfig overrides the default config loaded from disk.
func WithConfig(cfg config.Config) RunnerOption {
	return func(r *runnerImpl) { r.Config = cfg }
}

// WithCorrelationID sets an explicit correlation ID instead of generating one.
func WithCorrelationID(id uuid.UUID) RunnerOption {
	return func(r *runnerImpl) { r.UniqueCorrelationID = id }
}

// WithS3Backend configures the runner to store both Terraform state and
// Stratus internal state in an S3 bucket. Replaces the default filesystem
// state manager and injects backend credentials into the TerraformManager.
func WithS3Backend(cfg state.S3BackendConfig) RunnerOption {
	return func(r *runnerImpl) {
		s3State := state.NewS3StateManager(r.Technique, cfg)
		r.StateManager = s3State
		r.terraformBackendConfigs = s3State.BackendConfigs()
	}
}

type runnerImpl struct {
	Technique               *stratus.AttackTechnique
	TechniqueState          stratus.AttackTechniqueState
	TerraformDir            string
	ShouldForce             bool
	Config                  config.Config
	TerraformManager        TerraformManager
	StateManager            state.StateManager
	ProviderFactory         stratus.CloudProviders
	UniqueCorrelationID     uuid.UUID
	Context                 context.Context
	terraformBackendConfigs map[string]string
}

type Runner interface {
	WarmUp() (map[string]string, error)
	Detonate() error
	Revert() error
	CleanUp() error
	GetState() stratus.AttackTechniqueState
	GetUniqueExecutionId() string
}

var _ Runner = &runnerImpl{}

func NewRunner(technique *stratus.AttackTechnique, force bool, opts ...RunnerOption) Runner {
	return NewRunnerWithContext(context.Background(), technique, force, opts...)
}

func NewRunnerWithContext(ctx context.Context, technique *stratus.AttackTechnique, force bool, opts ...RunnerOption) Runner {
	runner := &runnerImpl{
		Technique:   technique,
		ShouldForce: force,
		Context:     ctx,
	}

	// Apply caller-provided overrides before filling defaults, to skip expensive initialization
	// (Terraform download, config loading) for dependencies the caller already supplies.
	for _, opt := range opts {
		opt(runner)
	}

	if runner.UniqueCorrelationID == uuid.Nil {
		runner.UniqueCorrelationID = resolveCorrelationID()
	}

	if runner.Config == nil {
		cfg, err := config.LoadConfig()
		if err != nil {
			log.Fatalf("error loading config: %s", err)
		}
		runner.Config = cfg
	}

	if runner.StateManager == nil {
		runner.StateManager = state.NewFileSystemStateManager(technique)
	}

	if runner.TerraformManager == nil {
		terraformBinaryPath := filepath.Join(runner.StateManager.GetRootDirectory(), "terraform")
		if envPath := os.Getenv(EnvVarStratusTerraformBinaryPath); envPath != "" {
			terraformBinaryPath = envPath
		}
		var tfOpts []TerraformManagerOption
		if len(runner.terraformBackendConfigs) > 0 {
			tfOpts = append(tfOpts, WithBackendConfigs(runner.terraformBackendConfigs))
		}
		runner.TerraformManager = NewTerraformManagerWithContext(
			ctx,
			terraformBinaryPath,
			useragent.GetStratusUserAgentForUUID(runner.UniqueCorrelationID),
			tfOpts...,
		)
	}

	runner.initialize()

	return runner
}

// resolveCorrelationID returns the correlation ID from the environment variable
// STRATUS_RED_TEAM_CORRELATION_ID (or the deprecated STRATUS_RED_TEAM_DETONATION_ID)
// if set and valid, otherwise generates a new one.
func resolveCorrelationID() uuid.UUID {
	raw := os.Getenv(EnvVarStratusRedTeamCorrelationId)
	envName := EnvVarStratusRedTeamCorrelationId
	if raw == "" {
		if raw = os.Getenv(EnvVarStratusRedTeamDetonationId); raw != "" {
			envName = EnvVarStratusRedTeamDetonationId
			log.Printf("WARNING: %s is deprecated, use %s instead", EnvVarStratusRedTeamDetonationId, EnvVarStratusRedTeamCorrelationId)
		}
	}
	if raw == "" {
		return uuid.New()
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		log.Printf("%s is not a valid UUID, using a random one: %s", envName, err.Error())
		return uuid.New()
	}
	return parsed
}

func (m *runnerImpl) initialize() {
	m.TerraformDir = filepath.Join(m.StateManager.GetRootDirectory(), m.Technique.ID)
	m.TechniqueState = m.StateManager.GetTechniqueState()
	if m.TechniqueState == "" {
		m.TechniqueState = stratus.AttackTechniqueStatusCold
	}
	// Only set default provider factory if not already injected
	if m.ProviderFactory == nil {
		m.ProviderFactory = stratus.CloudProvidersImpl{UniqueCorrelationID: m.UniqueCorrelationID}
	}
}

func (m *runnerImpl) WarmUp() (map[string]string, error) {
	// No prerequisites to spin-up
	if m.Technique.PrerequisitesTerraformCode == nil {
		return map[string]string{}, nil
	}

	err := m.StateManager.ExtractTechnique()
	if err != nil {
		return nil, errors.New("unable to extract Terraform file: " + err.Error())
	}

	// We don't want to warm up the technique
	var willWarmUp = true

	// Technique is already warm
	if m.TechniqueState == stratus.AttackTechniqueStatusWarm && !m.ShouldForce {
		log.Println("Not warming up - " + m.Technique.ID + " is already warm. Use --force to force")
		willWarmUp = false
	}

	if m.TechniqueState == stratus.AttackTechniqueStatusDetonated {
		log.Println(m.Technique.ID + " has been detonated but not cleaned up, not warming up as it should be warm already.")
		willWarmUp = false
	}

	if !willWarmUp {
		outputs, err := m.StateManager.GetTerraformOutputs()
		return outputs, err
	}

	log.Println("Warming up " + m.Technique.ID)
	overrideVars := m.buildTerraformVariables()
	outputs, err := m.TerraformManager.TerraformInitAndApply(m.TerraformDir, overrideVars)
	if err != nil {
		log.Println("Error during warm up. Cleaning up technique prerequisites with terraform destroy")
		_ = m.TerraformManager.TerraformDestroy(m.TerraformDir, overrideVars)
		// Drop the technique directory and any managed artifacts so a failed
		// warm-up does not leak a terraform.tfstate: on warmup failure TF sets
		// the `resource` key of the tfstate file to an empty array but doesn't
		// delete it.
		if cleanupErr := m.StateManager.CleanupTechnique(); cleanupErr != nil {
			log.Println("Warning: failed to remove technique state after failed warm up: " + cleanupErr.Error())
		}
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, errors.New("unable to run terraform apply on prerequisite: " + errorMessageFromTerraformError(err))
	}

	// Resources are created, set state to warm
	m.setState(stratus.AttackTechniqueStatusWarm)
	if display, ok := outputs["display"]; ok {
		display := strings.ReplaceAll(display, "\\n", "\n")
		log.Println(display)
	}

	// Persist outputs and variables to disk
	err = m.StateManager.WriteTerraformOutputs(outputs)
	if err != nil {
		return nil, errors.New("unable to persist Terraform outputs: " + err.Error())
	}
	if len(overrideVars) > 0 {
		err = m.StateManager.WriteTerraformVariables(overrideVars)
		if err != nil {
			return nil, errors.New("unable to persist Terraform variables: " + err.Error())
		}
	}

	return outputs, nil
}

func (m *runnerImpl) Detonate() error {
	willWarmUp := true
	var err error
	var outputs map[string]string

	// If the attack technique has already been detonated, make sure it's idempotent
	if m.GetState() == stratus.AttackTechniqueStatusDetonated {
		if !m.Technique.IsIdempotent && !m.ShouldForce {
			return errors.New(m.Technique.ID + " has already been detonated and is not idempotent. " +
				"Revert it with 'stratus revert' before detonating it again, or use --force")
		}
		willWarmUp = false
	}

	if m.Technique.IsSlow {
		log.Println("Note: This is a slow attack technique, it might take a long time to warm up or detonate")
	}

	if willWarmUp {
		outputs, err = m.WarmUp()
	} else {
		outputs, err = m.StateManager.GetTerraformOutputs()
	}

	if err != nil {
		return err
	}

	// Detonate
	err = m.Technique.Detonate(outputs, m.ProviderFactory)
	if err != nil {
		return errors.New("Error while detonating attack technique " + m.Technique.ID + ": " + err.Error())
	}
	m.setState(stratus.AttackTechniqueStatusDetonated)
	return nil
}

func (m *runnerImpl) Revert() error {
	if m.GetState() != stratus.AttackTechniqueStatusDetonated && !m.ShouldForce {
		return errors.New(m.Technique.ID + " is not in DETONATED state and should not need to be reverted, use --force to force")
	}

	outputs, err := m.StateManager.GetTerraformOutputs()
	if err != nil {
		return errors.New("unable to retrieve outputs of " + m.Technique.ID + ": " + err.Error())
	}

	log.Println("Reverting detonation of technique " + m.Technique.ID)

	if m.Technique.Revert != nil {
		err = m.Technique.Revert(outputs, m.ProviderFactory)
		if err != nil {
			return errors.New("unable to revert detonation of " + m.Technique.ID + ": " + err.Error())
		}
	}

	m.setState(stratus.AttackTechniqueStatusWarm)

	return nil
}

func (m *runnerImpl) CleanUp() error {
	// Has the technique already been cleaned up?
	if m.TechniqueState == stratus.AttackTechniqueStatusCold && !m.ShouldForce {
		return errors.New(m.Technique.ID + " is already COLD and should already be clean, use --force to force cleanup")
	}

	log.Println("Cleaning up " + m.Technique.ID)

	// Revert detonation
	if m.Technique.Revert != nil && m.GetState() == stratus.AttackTechniqueStatusDetonated {
		err := m.Revert()
		if err != nil {
			if m.ShouldForce {
				log.Println("Warning: failed to revert detonation of " + m.Technique.ID + ". Ignoring and cleaning up anyway as --force was used.")
			} else {
				return errors.New("unable to revert detonation of " + m.Technique.ID + " before cleaning up (use --force to cleanup anyway): " + err.Error())
			}
		}
	}

	// Nuke prerequisites
	if m.Technique.PrerequisitesTerraformCode != nil {
		// Ensure TF files are on disk
		if err := m.StateManager.ExtractTechnique(); err != nil {
			return errors.New("unable to extract Terraform files for cleanup: " + err.Error())
		}

		// Load persisted Terraform variables. We don't use the variables from the config file, that
		// may have changed since warmup, so we rely only on the persisted variables.
		persistedVars, err := m.StateManager.GetTerraformVariables()
		if err != nil {
			log.Println("Warning: unable to load persisted Terraform variables: " + err.Error())
		}

		log.Println("Cleaning up technique prerequisites with terraform destroy")
		err = m.TerraformManager.TerraformDestroy(m.TerraformDir, persistedVars)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			return errors.New("unable to cleanup TTP prerequisites: " + errorMessageFromTerraformError(err))
		}
	}

	m.setState(stratus.AttackTechniqueStatusCold)

	// Remove terraform directory
	err := m.StateManager.CleanupTechnique()
	if err != nil {
		return errors.New("unable to remove technique directory " + m.TerraformDir + ": " + err.Error())
	}

	return nil
}

func (m *runnerImpl) GetState() stratus.AttackTechniqueState {
	return m.TechniqueState
}

func (m *runnerImpl) setState(state stratus.AttackTechniqueState) {
	err := m.StateManager.SetTechniqueState(state)
	if err != nil {
		log.Println("Warning: unable to set technique state: " + err.Error())
	}
	m.TechniqueState = state
}

// GetUniqueExecutionId returns an unique execution ID, unique for each runner instance
func (m *runnerImpl) GetUniqueExecutionId() string {
	return m.UniqueCorrelationID.String()
}

// buildTerraformVariables returns the terraform variables to use,
// including the correlation metadata and any config-file overrides.
func (m *runnerImpl) buildTerraformVariables() map[string]string {
	correlationID := m.UniqueCorrelationID.String()
	vars := m.Config.GetTerraformVariables(m.Technique.ID, config.SubstitutionVars{CorrelationID: correlationID})
	if vars == nil {
		vars = make(map[string]string)
	}
	vars[state.TerraformCorrelationVarName] = state.MarshalCorrelation(correlationID)
	return vars
}

// Utility function to display better error messages than the Terraform ones
func errorMessageFromTerraformError(err error) string {
	const MissingRegionErrorMessage = "The argument \"region\" is required, but no definition was found"

	if strings.Contains(err.Error(), MissingRegionErrorMessage) {
		return "unable to create attack technique prerequisites. Ensure you are authenticated against AWS and have the right permissions to run Stratus Red Team.\n" +
			"Stratus Red Team will display below the error that Terraform returned:\n" + err.Error()
	}

	return err.Error()
}
