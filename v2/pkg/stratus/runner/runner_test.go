package runner

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/datadog/stratus-red-team/v2/internal/state"
	statemocks "github.com/datadog/stratus-red-team/v2/internal/state/mocks"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	configmocks "github.com/datadog/stratus-red-team/v2/pkg/stratus/config/mocks"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var testCorrelationID = uuid.MustParse("11111111-2222-3333-4444-555555555555")

func varsHaveCorrelation(id uuid.UUID) any {
	expected := state.MarshalCorrelation(id)
	return mock.MatchedBy(func(vars map[string]string) bool {
		return vars[state.TerraformCorrelationVarName] == expected
	})
}

func TestRunnerWarmUp(t *testing.T) {

	type RunnerWarmupTestScenario struct {
		Name                  string
		Technique             *stratus.AttackTechnique
		ShouldForce           bool
		InitialTechniqueState stratus.AttackTechniqueState
		TerraformOutputs      map[string]string
		PersistedOutputs      map[string]string
		Error                 error
		// results
		CheckExpectations func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error)
	}

	var scenario = []RunnerWarmupTestScenario{
		{
			Name:                  "Warming up a technique without prerequisite Terraform code",
			Technique:             &stratus.AttackTechnique{ID: "foo"},
			InitialTechniqueState: stratus.AttackTechniqueStatusCold,
			PersistedOutputs:      map[string]string{"myoutput": "foo"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply", mock.Anything, mock.Anything)
				state.AssertNotCalled(t, "ExtractTechnique")
				assert.Nil(t, err)

				// No prerequisite Terraform code implies there cannot be any output
				assert.Len(t, outputs, 0)
			},
		},
		{
			Name:                  "Warming up a COLD technique",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo")},
			InitialTechniqueState: stratus.AttackTechniqueStatusCold,
			TerraformOutputs:      map[string]string{"myoutput": "new"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				state.AssertCalled(t, "ExtractTechnique")
				terraform.AssertCalled(t, "TerraformInitAndApply", "/root/foo", varsHaveCorrelation(testCorrelationID))
				state.AssertCalled(t, "WriteTerraformOutputs", map[string]string{"myoutput": "new"})
				state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusWarm))
				state.AssertNotCalled(t, "CleanupTechnique")

				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "new", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a WARM technique without force flag",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: stratus.AttackTechniqueStatusWarm,
			PersistedOutputs:      map[string]string{"myoutput": "new"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply", mock.Anything, mock.Anything)
				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "new", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a WARM technique with force flag",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			ShouldForce:           true,
			InitialTechniqueState: stratus.AttackTechniqueStatusWarm,
			TerraformOutputs:      map[string]string{"myoutput": "old"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertCalled(t, "TerraformInitAndApply", "/root/foo", varsHaveCorrelation(testCorrelationID))
				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "old", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a DETONATED technique",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: stratus.AttackTechniqueStatusDetonated,
			PersistedOutputs:      map[string]string{"myoutput": "old"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply", mock.Anything, mock.Anything)
				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "old", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a COLD technique with error",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: stratus.AttackTechniqueStatusCold,
			Error:                 errors.New("error during init and apply"),
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertCalled(t, "TerraformInitAndApply", "/root/foo", varsHaveCorrelation(testCorrelationID))
				terraform.AssertCalled(t, "TerraformDestroy", "/root/foo", varsHaveCorrelation(testCorrelationID))
				state.AssertCalled(t, "CleanupTechnique")
				assert.NotNil(t, err)
				assert.Len(t, outputs, 0)
			},
		},
	}

	for i := range scenario {
		config := new(configmocks.Config)
		state := new(statemocks.StateManager)
		terraform := new(mocks.TerraformManager)

		config.On("GetTerraformVariables", mock.Anything, mock.Anything).Return(map[string]string{})
		state.On("GetWorkingDirectory").Return("/root/foo")
		state.On("ExtractTechnique").Return(nil)
		state.On("GetTechniqueState", mock.Anything).Return(scenario[i].InitialTechniqueState, nil)
		state.On("GetTerraformOutputs").Return(scenario[i].PersistedOutputs, nil)
		terraform.On("TerraformInitAndApply", mock.Anything, mock.Anything).Return(scenario[i].TerraformOutputs, scenario[i].Error)
		terraform.On("TerraformDestroy", mock.Anything, mock.Anything).Return(nil)
		state.On("WriteTerraformOutputs", mock.Anything).Return(nil)
		state.On("WriteTerraformVariables", mock.Anything).Return(nil)
		state.On("SetTechniqueState", mock.Anything).Return(nil)
		state.On("CleanupTechnique").Return(nil)

		runner := runnerImpl{
			Technique:           scenario[i].Technique,
			ShouldForce:         scenario[i].ShouldForce,
			Config:              config,
			TerraformManager:    terraform,
			StateManager:        state,
			UniqueCorrelationID: testCorrelationID,
		}
		runner.initialize()
		outputs, err := runner.WarmUp()
		t.Run(scenario[i].Name, func(t *testing.T) { scenario[i].CheckExpectations(t, terraform, state, outputs, err) })
	}
}

func TestRunnerDetonate(t *testing.T) {

	type TestDetonationScenario struct {
		Name                            string
		TechniqueState                  stratus.AttackTechniqueState
		IsIdempotent                    bool
		Force                           bool
		ExpectDetonated                 bool
		ExpectWarmedUp                  bool
		ExpectError                     bool
		ExpectedStateChangedToDetonated bool
	}

	scenario := []TestDetonationScenario{
		{
			Name:                            "DetonateWarmIdempotentAttackTechnique",
			TechniqueState:                  stratus.AttackTechniqueStatusWarm,
			IsIdempotent:                    true,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
		{
			Name:                            "DetonateWarmNonIdempotentAttackTechnique",
			TechniqueState:                  stratus.AttackTechniqueStatusWarm,
			IsIdempotent:                    false,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
		{
			Name:                            "DetonateDetonatedIdempotentAttackTechnique",
			TechniqueState:                  stratus.AttackTechniqueStatusDetonated,
			IsIdempotent:                    true,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
		{
			Name:                            "DetonateDetonatedNonIdempotentAttackTechnique",
			TechniqueState:                  stratus.AttackTechniqueStatusDetonated,
			IsIdempotent:                    false,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 false,
			ExpectError:                     true,
			ExpectedStateChangedToDetonated: false,
		},
		{
			Name:                            "DetonateDetonatedNonIdempotentAttackTechniqueWithForceFlag",
			TechniqueState:                  stratus.AttackTechniqueStatusDetonated,
			IsIdempotent:                    false,
			Force:                           true,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			config := new(configmocks.Config)
			state := new(statemocks.StateManager)
			terraform := new(mocks.TerraformManager)

			config.On("GetTerraformVariables", mock.Anything, mock.Anything).Return(map[string]string{})
			state.On("GetWorkingDirectory").Return("/root/sample-technique")
			state.On("ExtractTechnique").Return(nil)
			state.On("GetTechniqueState", mock.Anything).Return(scenario[i].TechniqueState, nil)
			terraform.On("TerraformInitAndApply", mock.Anything, mock.Anything).Return(map[string]string{}, nil)
			state.On("WriteTerraformOutputs", mock.Anything).Return(nil)
			state.On("WriteTerraformVariables", mock.Anything).Return(nil)
			state.On("GetTerraformOutputs").Return(map[string]string{}, nil)
			state.On("SetTechniqueState", mock.Anything).Return(nil)

			var wasDetonated = false
			runner := runnerImpl{
				UniqueCorrelationID: testCorrelationID,
				Technique: &stratus.AttackTechnique{
					ID: "sample-technique",
					Detonate: func(map[string]string, stratus.CloudProviders) error {
						wasDetonated = true
						return nil
					},
					IsIdempotent: scenario[i].IsIdempotent,
				},
				ShouldForce:      scenario[i].Force,
				Config:           config,
				TerraformManager: terraform,
				StateManager:     state,
			}
			runner.initialize()
			err := runner.Detonate()

			if scenario[i].ExpectError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if scenario[i].ExpectWarmedUp {
				terraform.AssertCalled(t, "TerraformInitAndApply", mock.Anything, mock.Anything)
			} else {
				terraform.AssertNotCalled(t, "TerraformInitAndApply", mock.Anything, mock.Anything)
			}

			if scenario[i].ExpectDetonated {
				assert.True(t, wasDetonated)
			} else {
				assert.False(t, wasDetonated)
			}

			if scenario[i].ExpectedStateChangedToDetonated {
				state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusDetonated))
			} else {
				state.AssertNotCalled(t, "SetTechniqueState", mock.Anything)
			}
		})
	}
}

func TestRunnerRevert(t *testing.T) {
	type TestRevertScenario struct {
		Name                        string
		TechniqueState              stratus.AttackTechniqueState
		Force                       bool
		ExpectDidCallRevertFunction bool
		ExpectDidChangeStateToWarm  bool
		ExpectError                 bool
	}
	scenario := []TestRevertScenario{
		{
			Name:                        "DetonatedTechniqueIsReverted",
			TechniqueState:              stratus.AttackTechniqueStatusDetonated,
			Force:                       false,
			ExpectDidCallRevertFunction: true,
			ExpectDidChangeStateToWarm:  true,
			ExpectError:                 false,
		},
		{
			Name:                        "WarmTechniqueIsNotReverted",
			TechniqueState:              stratus.AttackTechniqueStatusWarm,
			Force:                       false,
			ExpectDidCallRevertFunction: false,
			ExpectDidChangeStateToWarm:  false,
			ExpectError:                 true,
		},
		{
			Name:                        "WarmTechniqueIsRevertedWithForce",
			TechniqueState:              stratus.AttackTechniqueStatusWarm,
			Force:                       true,
			ExpectDidCallRevertFunction: true,
			ExpectDidChangeStateToWarm:  true,
			ExpectError:                 false,
		},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			state := new(statemocks.StateManager)
			state.On("GetWorkingDirectory").Return("/root/foo")
			state.On("ExtractTechnique").Return(nil)
			state.On("GetTerraformOutputs").Return(map[string]string{"foo": "bar"}, nil)
			state.On("GetTechniqueState", mock.Anything).Return(scenario[i].TechniqueState)
			state.On("SetTechniqueState", mock.Anything).Return(nil)

			var wasReverted = false
			runner := runnerImpl{
				Technique: &stratus.AttackTechnique{
					ID:       "foo",
					Detonate: func(map[string]string, stratus.CloudProviders) error { return nil },
					Revert: func(params map[string]string, factory stratus.CloudProviders) error {
						wasReverted = true
						return nil
					},
				},
				ShouldForce:  scenario[i].Force,
				StateManager: state,
			}
			runner.initialize()

			err := runner.Revert()

			if scenario[i].ExpectError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if scenario[i].ExpectDidCallRevertFunction {
				assert.True(t, wasReverted)
			} else {
				assert.False(t, wasReverted)
			}

			if scenario[i].ExpectDidChangeStateToWarm {
				state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusWarm))
			} else {
				state.AssertNotCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusWarm))
			}
		})
	}

}

func TestRunnerCleanup(t *testing.T) {
	type RunnerCleanupTestScenario struct {
		Name                  string
		Technique             *stratus.AttackTechnique
		ShouldForce           bool
		InitialTechniqueState stratus.AttackTechniqueState
		TerraformDestroyFails bool
		RevertFails           bool
		// results
		CheckExpectations func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error)
	}

	var scenario = []RunnerCleanupTestScenario{
		{
			Name:                  "Cleaning up an already cold technique without force flag",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: stratus.AttackTechniqueStatusCold,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.NotNil(t, err)
				terraform.AssertNotCalled(t, "TerraformDestroy", mock.Anything, mock.Anything)
				state.AssertNotCalled(t, "CleanupTechnique")
			},
		},
		{

			Name:                  "Cleaning up an already cold technique with force flag",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: stratus.AttackTechniqueStatusCold,
			ShouldForce:           true,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.Nil(t, err)
				terraform.AssertCalled(t, "TerraformDestroy", mock.Anything, mock.Anything)
				state.AssertCalled(t, "CleanupTechnique")
			},
		},
		{
			Name:                  "Cleaning up a WARM technique",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: stratus.AttackTechniqueStatusWarm,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.Nil(t, err)
				terraform.AssertCalled(t, "TerraformDestroy", mock.Anything, mock.Anything)
				state.AssertCalled(t, "CleanupTechnique")
				state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))
			},
		},
		{
			Name:                  "Cleaning up a DETONATED technique and terraform destroy fails",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: stratus.AttackTechniqueStatusDetonated,
			TerraformDestroyFails: true,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.NotNil(t, err, "terraform destroy error should be propagated")

				// The technique should not have been marked as properly cleaned up
				state.AssertNotCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))
			},
		},
		{
			Name:                  "Cleaning up a DETONATED technique and revert fails",
			Technique:             &stratus.AttackTechnique{ID: "foo"},
			InitialTechniqueState: stratus.AttackTechniqueStatusDetonated,
			RevertFails:           true,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.NotNil(t, err, "revert error should be propagated")

				// The technique should not have been marked as properly cleaned up
				state.AssertNotCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))
			},
		},
		{
			Name:                  "Cleaning up a DETONATED technique with force flag and revert fails",
			Technique:             &stratus.AttackTechnique{ID: "foo"},
			InitialTechniqueState: stratus.AttackTechniqueStatusDetonated,
			ShouldForce:           true,
			RevertFails:           true,
			TerraformDestroyFails: false,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.Nil(t, err, "revert error should not be propagated")

				// Cleanup is a superset of revert, so the technique ends up fully cleaned up.
				state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))
			},
		},
	}

	for i := range scenario {
		state := new(statemocks.StateManager)
		terraform := new(mocks.TerraformManager)

		state.On("GetTerraformVariables").Return(map[string]string{}, nil)
		state.On("GetWorkingDirectory").Return("/root/foo")
		state.On("ExtractTechnique").Return(nil)
		state.On("GetTechniqueState", mock.Anything).Return(scenario[i].InitialTechniqueState, nil)
		state.On("SetTechniqueState", mock.Anything).Return(nil)
		state.On("CleanupTechnique").Return(nil)
		state.On("GetTerraformOutputs").Return(map[string]string{}, nil)
		if scenario[i].TerraformDestroyFails {
			terraform.On("TerraformDestroy", mock.Anything, mock.Anything).Return(errors.New("nope"))
		} else {
			terraform.On("TerraformDestroy", mock.Anything, mock.Anything).Return(nil)
		}
		if scenario[i].RevertFails {
			scenario[i].Technique.Revert = func(map[string]string, stratus.CloudProviders) error {
				return errors.New("nope")
			}
		}
		runner := runnerImpl{
			Technique:        scenario[i].Technique,
			ShouldForce:      scenario[i].ShouldForce,
			TerraformManager: terraform,
			StateManager:     state,
		}
		runner.initialize()
		err := runner.CleanUp()
		t.Run(scenario[i].Name, func(t *testing.T) { scenario[i].CheckExpectations(t, terraform, state, err) })
	}
}

// TestNewRunnerWithOptions verifies that injected dependencies are used
// instead of the defaults (filesystem state, downloaded Terraform, etc.).
func TestNewRunnerWithOptions(t *testing.T) {
	stateMock := new(statemocks.StateManager)
	tfMock := new(mocks.TerraformManager)
	configMock := new(configmocks.Config)
	correlationID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

	stateMock.On("GetWorkingDirectory").Return("/custom/root/test.technique")
	stateMock.On("GetTechniqueState").Return(stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))

	technique := &stratus.AttackTechnique{ID: "test.technique"}

	r := NewRunnerWithContext(
		context.Background(),
		technique,
		false,
		WithStateManager(stateMock),
		WithTerraformManager(tfMock),
		WithConfig(configMock),
		WithCorrelationID(correlationID),
	)

	assert.Equal(t, stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold), r.GetState())
	assert.Equal(t, correlationID.String(), r.GetUniqueExecutionId())

	// Verify the injected state manager was actually called during init
	stateMock.AssertCalled(t, "GetWorkingDirectory")
	stateMock.AssertCalled(t, "GetTechniqueState")
}

// TestNewRunnerWithProviderFactory verifies that an injected provider factory
// is preserved and not overwritten by the default.
func TestNewRunnerWithProviderFactory(t *testing.T) {
	stateMock := new(statemocks.StateManager)
	tfMock := new(mocks.TerraformManager)
	configMock := new(configmocks.Config)

	stateMock.On("GetWorkingDirectory").Return("/root/test.provider-injection")
	stateMock.On("GetTechniqueState").Return(stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))

	customProviders := stratus.CloudProvidersImpl{
		UniqueCorrelationID: testCorrelationID,
	}

	technique := &stratus.AttackTechnique{
		ID:                         "test.provider-injection",
		PrerequisitesTerraformCode: []byte("resource {}"),
		Detonate: func(params map[string]string, pf stratus.CloudProviders) error {
			// Verify we got the injected provider, not a default one
			assert.Equal(t, customProviders, pf)
			return nil
		},
	}

	stateMock.On("ExtractTechnique").Return(nil)
	stateMock.On("GetTerraformOutputs").Return(map[string]string{}, nil)
	stateMock.On("SetTechniqueState", mock.Anything).Return(nil)
	stateMock.On("WriteTerraformOutputs", mock.Anything).Return(nil)
	stateMock.On("WriteTerraformVariables", mock.Anything).Return(nil)
	configMock.On("GetTerraformVariables", mock.Anything, mock.Anything).Return(map[string]string{})
	tfMock.On("TerraformInitAndApply", mock.Anything, mock.Anything).Return(map[string]string{}, nil)

	r := NewRunnerWithContext(
		context.Background(),
		technique,
		false,
		WithStateManager(stateMock),
		WithTerraformManager(tfMock),
		WithConfig(configMock),
		WithProviderFactory(customProviders),
	)

	// Detonate calls the technique's Detonate function, which asserts
	// that the injected provider factory was passed through.
	err := r.Detonate()
	assert.Nil(t, err)
}

// TestProviderCredentialInjection demonstrates the full credential injection
// flow: build providers with explicit credentials, pre-populate
// CloudProvidersImpl, and pass it to the runner via WithProviderFactory.
// This is the pattern Cumulus uses to run techniques with per-execution
// credentials instead of relying on environment variables.
func TestProviderCredentialInjection(t *testing.T) {
	stateMock := new(statemocks.StateManager)
	tfMock := new(mocks.TerraformManager)
	configMock := new(configmocks.Config)
	correlationID := uuid.New()

	stateMock.On("GetWorkingDirectory").Return("/root/test.credential-injection")
	stateMock.On("GetTechniqueState").Return(stratus.AttackTechniqueState(stratus.AttackTechniqueStatusCold))
	stateMock.On("ExtractTechnique").Return(nil)
	stateMock.On("GetTerraformOutputs").Return(map[string]string{}, nil)
	stateMock.On("SetTechniqueState", mock.Anything).Return(nil)
	stateMock.On("WriteTerraformOutputs", mock.Anything).Return(nil)
	stateMock.On("WriteTerraformVariables", mock.Anything).Return(nil)
	configMock.On("GetTerraformVariables", mock.Anything, mock.Anything).Return(map[string]string{})
	tfMock.On("TerraformInitAndApply", mock.Anything, mock.Anything).Return(map[string]string{}, nil)

	// Build an AWS provider with explicit static credentials using the
	// public API (same functions available to external consumers)
	awsCfg := stratus.AWSConfigFromCredentials(
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"",
		&correlationID,
	)
	awsProvider := stratus.NewAWSProvider(correlationID, stratus.WithAWSConfig(awsCfg))

	// Pre-populate CloudProvidersImpl with the explicitly-credentialed
	// provider. Other providers (K8s, Azure, etc.) are left nil and would
	// be lazily initialized from defaults if a technique needed them.
	customFactory := stratus.CloudProvidersImpl{
		UniqueCorrelationID: correlationID,
		AWSProvider:         awsProvider,
	}

	var receivedConfig aws.Config
	technique := &stratus.AttackTechnique{
		ID:                         "test.credential-injection",
		PrerequisitesTerraformCode: []byte("resource {}"),
		Detonate: func(params map[string]string, pf stratus.CloudProviders) error {
			receivedConfig = pf.AWS().GetConnection()
			return nil
		},
	}

	r := NewRunnerWithContext(
		context.Background(),
		technique,
		false,
		WithStateManager(stateMock),
		WithTerraformManager(tfMock),
		WithConfig(configMock),
		WithProviderFactory(customFactory),
	)

	err := r.Detonate()
	assert.Nil(t, err)

	// Verify the injected credentials made it through to the Detonate
	// function — the provider should use our explicit config, not the
	// default credential chain.
	creds, err := receivedConfig.Credentials.Retrieve(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", creds.AccessKeyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", creds.SecretAccessKey)
}

// Whether the correlation ID was *provided* decides the state layout, so it must be
// distinguishable from a generated one. A generated ID differs on every command and could
// never find the state written by a previous step.
func TestResolveCorrelationID(t *testing.T) {
	const providedID = "aabcdefa-1234-5678-9012-abcdef012345"
	const otherID = "ffffffff-1234-5678-9012-abcdef012345"

	scenario := []struct {
		Name             string
		CorrelationIDEnv string
		DetonationIDEnv  string
		ExpectedProvided bool
		// Empty means the ID is generated, so only its presence can be asserted.
		ExpectedID string
	}{
		{Name: "neither variable set", ExpectedProvided: false},
		{Name: "correlation id set", CorrelationIDEnv: providedID, ExpectedProvided: true, ExpectedID: providedID},
		{Name: "deprecated detonation id set", DetonationIDEnv: providedID, ExpectedProvided: true, ExpectedID: providedID},
		{Name: "correlation id wins over deprecated", CorrelationIDEnv: providedID, DetonationIDEnv: otherID, ExpectedProvided: true, ExpectedID: providedID},
		{Name: "invalid uuid is not provided", CorrelationIDEnv: "not-a-uuid", ExpectedProvided: false},
		{Name: "empty value is not provided", CorrelationIDEnv: "", ExpectedProvided: false},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			t.Setenv(EnvVarStratusRedTeamCorrelationId, scenario[i].CorrelationIDEnv)
			t.Setenv(EnvVarStratusRedTeamDetonationId, scenario[i].DetonationIDEnv)

			id, provided := resolveCorrelationID()

			assert.Equal(t, scenario[i].ExpectedProvided, provided)
			if scenario[i].ExpectedID != "" {
				assert.Equal(t, scenario[i].ExpectedID, id.String())
			} else {
				assert.NotEqual(t, uuid.Nil, id)
			}
		})
	}
}

// The layout decision is the whole point of correlation-scoped state, and every other test here
// injects a state manager and so skips it. This exercises the real FileSystemStateManager.
func TestRunnerStateLayoutFollowsCorrelationID(t *testing.T) {
	const providedID = "aabcdefa-1234-5678-9012-abcdef012345"
	technique := &stratus.AttackTechnique{ID: "aws.test.layout"}

	scenario := []struct {
		Name             string
		CorrelationIDEnv string
		DetonationIDEnv  string
		Option           []RunnerOption
		ExpectNestedDir  string
	}{
		{Name: "no correlation id keeps the flat layout"},
		{Name: "correlation id from the environment nests", CorrelationIDEnv: providedID, ExpectNestedDir: providedID},
		{Name: "deprecated variable nests too", DetonationIDEnv: providedID, ExpectNestedDir: providedID},
		{Name: "WithCorrelationID nests", Option: []RunnerOption{WithCorrelationID(uuid.MustParse(providedID))}, ExpectNestedDir: providedID},
		{Name: "WithCorrelationID(Nil) falls back to a generated id", Option: []RunnerOption{WithCorrelationID(uuid.Nil)}},
		{Name: "an invalid correlation id does not isolate", CorrelationIDEnv: "not-a-uuid"},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv(EnvVarStratusRedTeamCorrelationId, scenario[i].CorrelationIDEnv)
			t.Setenv(EnvVarStratusRedTeamDetonationId, scenario[i].DetonationIDEnv)

			opts := append([]RunnerOption{WithTerraformManager(new(mocks.TerraformManager)), WithConfig(new(configmocks.Config))}, scenario[i].Option...)
			r := NewRunner(technique, StratusRunnerNoForce, opts...).(*runnerImpl)

			expected := filepath.Join(home, ".stratus-red-team", technique.ID)
			if scenario[i].ExpectNestedDir != "" {
				expected = filepath.Join(expected, scenario[i].ExpectNestedDir)
			}
			assert.Equal(t, expected, r.TerraformDir)
		})
	}
}

// A generated correlation ID must never isolate state: it differs on every command, so the
// working directory would move between warmup and cleanup.
func TestRunnerGeneratedCorrelationIDKeepsFlatLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvVarStratusRedTeamCorrelationId, "")
	t.Setenv(EnvVarStratusRedTeamDetonationId, "")
	technique := &stratus.AttackTechnique{ID: "aws.test.generated"}

	first := NewRunner(technique, StratusRunnerNoForce, WithTerraformManager(new(mocks.TerraformManager)), WithConfig(new(configmocks.Config))).(*runnerImpl)
	second := NewRunner(technique, StratusRunnerNoForce, WithTerraformManager(new(mocks.TerraformManager)), WithConfig(new(configmocks.Config))).(*runnerImpl)

	assert.NotEqual(t, first.GetUniqueExecutionId(), second.GetUniqueExecutionId())
	assert.Equal(t, first.TerraformDir, second.TerraformDir, "two commands must resolve to the same state")
}
