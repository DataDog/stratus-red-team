package runner

import (
	"context"
	"errors"
	"log"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/datadog/stratus-red-team/v2/internal/config"
	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"github.com/google/uuid"
)

const StratusRunnerForce = true
const StratusRunnerNoForce = false

const EnvVarStratusRedTeamDetonationId = "STRATUS_RED_TEAM_DETONATION_ID"

// RunnerOption is a functional option for configuring a Runner.
type RunnerOption func(r *runnerImpl)

// WithNamespace sets the namespace for Kubernetes/EKS techniques.
func WithNamespace(namespace string) RunnerOption {
	return func(r *runnerImpl) {
		if namespace != "" && (r.Technique.Platform == stratus.Kubernetes || r.Technique.Platform == stratus.EKS) {
			if r.TerraformVariables == nil {
				r.TerraformVariables = make(map[string]string)
			}
			r.TerraformVariables["namespace"] = namespace
		}
	}
}

type runnerImpl struct {
	Technique           *stratus.AttackTechnique
	TechniqueState      stratus.AttackTechniqueState
	TerraformDir        string
	ShouldForce         bool
	TerraformManager    TerraformManager
	TerraformVariables  map[string]string
	StateManager        state.StateManager
	ProviderFactory     stratus.CloudProviders
	UniqueCorrelationID uuid.UUID
	Context             context.Context
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
	stateManager := state.NewFileSystemStateManager(technique)

	var correlationId = uuid.New()
	var err error
	if grimoireDetonationId := os.Getenv("STRATUS_RED_TEAM_DETONATION_ID"); grimoireDetonationId != "" {
		log.Println("STRATUS_RED_TEAM_DETONATION_ID is set, using it as the correlation ID")
		correlationId, err = uuid.Parse(grimoireDetonationId)
		if err != nil {
			log.Println("STRATUS_RED_TEAM_DETONATION_ID is not a valid UUID, falling back to a randomly-generated one: " + err.Error())
			correlationId = uuid.New()
		}
	}

	runner := &runnerImpl{
		Technique:           technique,
		ShouldForce:         force,
		StateManager:        stateManager,
		UniqueCorrelationID: correlationId,
		TerraformManager: NewTerraformManagerWithContext(
			ctx, filepath.Join(stateManager.GetRootDirectory(), "terraform"), useragent.GetStratusUserAgentForUUID(correlationId),
		),
		Context: ctx,
	}

	for _, opt := range opts {
		opt(runner)
	}

	runner.initialize()

	return runner
}

func (m *runnerImpl) initialize() {
	m.TerraformDir = filepath.Join(m.StateManager.GetRootDirectory(), m.Technique.ID)
	m.TechniqueState = m.StateManager.GetTechniqueState()
	if m.TechniqueState == "" {
		m.TechniqueState = stratus.AttackTechniqueStatusCold
	}
	m.ProviderFactory = stratus.CloudProvidersImpl{UniqueCorrelationID: m.UniqueCorrelationID}
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
	mergedVars := m.getMergedTerraformVariables()
	outputs, err := m.TerraformManager.TerraformInitAndApply(m.TerraformDir, mergedVars)
	if err != nil {
		log.Println("Error during warm up. Cleaning up technique prerequisites with terraform destroy")
		_ = m.TerraformManager.TerraformDestroy(m.TerraformDir, mergedVars)
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
	if len(mergedVars) > 0 {
		err = m.StateManager.WriteTerraformVariables(mergedVars)
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
		// Load persisted Terraform variables from filesystem. We don't use the variables from the
		// config file, that may have change since warmup, so we rely only on the persisted variables.
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

// getMergedTerraformVariables returns the terraform variables to use by merging, in increasing order of precedence:
//  1. From config file: namespace for k8s techniques
//  2. From config file:Pod specific config (image, tolerations...) if technique has PodConfigViaTerraform
//  3. From CLI: Explicitly set variables via RunnerOptions
//
// Explicit variables take precedence over config file values.
func (m *runnerImpl) getMergedTerraformVariables() map[string]string {
	result := make(map[string]string)

	// Load config for k8s/EKS techniques
	if m.Technique.Platform == stratus.Kubernetes || m.Technique.Platform == stratus.EKS {
		cfg, err := config.LoadConfig()
		if err == nil && cfg != nil {
			// Always add namespace from config if set
			if cfg.Kubernetes.Namespace != "" {
				result["namespace"] = cfg.Kubernetes.Namespace
			}

			// Add pod config as TF variables if technique creates pods via Terraform
			if m.Technique.PodConfigViaTerraform {
				techniqueConfig := cfg.Kubernetes.GetTechniqueConfig(m.Technique.ID)
				if tfVars := techniqueConfig.ToTerraformVariables(); tfVars != nil {
					maps.Copy(result, tfVars)
				}
			}
		}
	}

	// Explicitly defined variables (from CLI) take precedence
	maps.Copy(result, m.TerraformVariables)

	if len(result) == 0 {
		return nil
	}
	return result
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
