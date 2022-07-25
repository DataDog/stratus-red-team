package runner

import (
	"errors"
	statemocks "github.com/datadog/stratus-red-team/v2/internal/state/mocks"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/domain"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestRunnerWarmUp(t *testing.T) {

	type RunnerWarmupTestScenario struct {
		Name                  string
		Technique             *domain.AttackTechnique
		ShouldForce           bool
		InitialTechniqueState domain.AttackTechniqueState
		TerraformOutputs      map[string]string
		PersistedOutputs      map[string]string
		// results
		CheckExpectations func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error)
	}

	var scenario = []RunnerWarmupTestScenario{
		{
			Name:                  "Warming up a technique without prerequisite Terraform code",
			Technique:             &domain.AttackTechnique{ID: "foo"},
			InitialTechniqueState: domain.AttackTechniqueStatusCold,
			PersistedOutputs:      map[string]string{"myoutput": "foo"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply")
				state.AssertNotCalled(t, "ExtractTechnique")
				assert.Nil(t, err)

				// No prerequisite Terraform code implies there cannot be any output
				assert.Len(t, outputs, 0)
			},
		},
		{
			Name:                  "Warming up a COLD technique",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo")},
			InitialTechniqueState: domain.AttackTechniqueStatusCold,
			TerraformOutputs:      map[string]string{"myoutput": "new"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				state.AssertCalled(t, "ExtractTechnique")
				terraform.AssertCalled(t, "TerraformInitAndApply", "/root/foo")
				state.AssertCalled(t, "WriteTerraformOutputs", map[string]string{"myoutput": "new"})
				state.AssertCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusWarm))

				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "new", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a WARM technique without force flag",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: domain.AttackTechniqueStatusWarm,
			PersistedOutputs:      map[string]string{"myoutput": "new"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply")
				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "new", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a WARM technique with force flag",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			ShouldForce:           true,
			InitialTechniqueState: domain.AttackTechniqueStatusWarm,
			TerraformOutputs:      map[string]string{"myoutput": "old"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertCalled(t, "TerraformInitAndApply", "/root/foo")
				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "old", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a DETONATED technique",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: domain.AttackTechniqueStatusDetonated,
			PersistedOutputs:      map[string]string{"myoutput": "old"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply")
				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "old", outputs["myoutput"])
			},
		},
	}

	for i := range scenario {
		state := new(statemocks.StateManager)
		terraform := new(mocks.TerraformManager)

		state.On("GetRootDirectory").Return("/root")
		state.On("ExtractTechnique").Return(nil)
		state.On("GetTechniqueState", mock.Anything).Return(scenario[i].InitialTechniqueState, nil)
		state.On("GetTerraformOutputs").Return(scenario[i].PersistedOutputs, nil)
		terraform.On("TerraformInitAndApply", mock.Anything).Return(scenario[i].TerraformOutputs, nil)
		state.On("WriteTerraformOutputs", mock.Anything).Return(nil)
		state.On("SetTechniqueState", mock.Anything).Return(nil)

		runner := Runner{
			Technique:        scenario[i].Technique,
			ShouldForce:      scenario[i].ShouldForce,
			TerraformManager: terraform,
			StateManager:     state,
		}
		runner.Initialize()
		outputs, err := runner.WarmUp()
		t.Run(scenario[i].Name, func(t *testing.T) { scenario[i].CheckExpectations(t, terraform, state, outputs, err) })
	}
}

func TestRunnerDetonate(t *testing.T) {

	type TestDetonationScenario struct {
		Name                            string
		TechniqueState                  domain.AttackTechniqueState
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
			TechniqueState:                  domain.AttackTechniqueStatusWarm,
			IsIdempotent:                    true,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
		{
			Name:                            "DetonateWarmNonIdempotentAttackTechnique",
			TechniqueState:                  domain.AttackTechniqueStatusWarm,
			IsIdempotent:                    false,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
		{
			Name:                            "DetonateDetonatedIdempotentAttackTechnique",
			TechniqueState:                  domain.AttackTechniqueStatusDetonated,
			IsIdempotent:                    true,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 true,
			ExpectError:                     false,
			ExpectedStateChangedToDetonated: true,
		},
		{
			Name:                            "DetonateDetonatedNonIdempotentAttackTechnique",
			TechniqueState:                  domain.AttackTechniqueStatusDetonated,
			IsIdempotent:                    false,
			Force:                           false,
			ExpectWarmedUp:                  false,
			ExpectDetonated:                 false,
			ExpectError:                     true,
			ExpectedStateChangedToDetonated: false,
		},
		{
			Name:                            "DetonateDetonatedNonIdempotentAttackTechniqueWithForceFlag",
			TechniqueState:                  domain.AttackTechniqueStatusDetonated,
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
			state := new(statemocks.StateManager)
			terraform := new(mocks.TerraformManager)

			state.On("GetRootDirectory").Return("/root")
			state.On("ExtractTechnique").Return(nil)
			state.On("GetTechniqueState", mock.Anything).Return(scenario[i].TechniqueState, nil)
			terraform.On("TerraformInitAndApply", mock.Anything).Return(map[string]string{}, nil)
			state.On("WriteTerraformOutputs", mock.Anything).Return(nil)
			state.On("GetTerraformOutputs").Return(map[string]string{}, nil)
			state.On("SetTechniqueState", mock.Anything).Return(nil)

			var wasDetonated = false
			runner := Runner{
				Technique: &domain.AttackTechnique{
					ID: "sample-technique",
					Detonate: func(domain.ProvidersFactory, map[string]string) error {
						wasDetonated = true
						return nil
					},
					IsIdempotent: scenario[i].IsIdempotent,
				},
				ShouldForce:      scenario[i].Force,
				TerraformManager: terraform,
				StateManager:     state,
			}
			runner.Initialize()
			err := runner.Detonate()

			if scenario[i].ExpectError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

			if scenario[i].ExpectWarmedUp {
				terraform.AssertCalled(t, "TerraformInitAndApply", mock.Anything)
			} else {
				terraform.AssertNotCalled(t, "TerraformInitAndApply", mock.Anything)
			}

			if scenario[i].ExpectDetonated {
				assert.True(t, wasDetonated)
			} else {
				assert.False(t, wasDetonated)
			}

			if scenario[i].ExpectedStateChangedToDetonated {
				state.AssertCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusDetonated))
			} else {
				state.AssertNotCalled(t, "SetTechniqueState", mock.Anything)
			}
		})
	}
}

func TestRunnerRevert(t *testing.T) {
	type TestRevertScenario struct {
		Name                        string
		TechniqueState              domain.AttackTechniqueState
		Force                       bool
		ExpectDidCallRevertFunction bool
		ExpectDidChangeStateToWarm  bool
		ExpectError                 bool
	}
	scenario := []TestRevertScenario{
		{
			Name:                        "DetonatedTechniqueIsReverted",
			TechniqueState:              domain.AttackTechniqueStatusDetonated,
			Force:                       false,
			ExpectDidCallRevertFunction: true,
			ExpectDidChangeStateToWarm:  true,
			ExpectError:                 false,
		},
		{
			Name:                        "WarmTechniqueIsNotReverted",
			TechniqueState:              domain.AttackTechniqueStatusWarm,
			Force:                       false,
			ExpectDidCallRevertFunction: false,
			ExpectDidChangeStateToWarm:  false,
			ExpectError:                 true,
		},
		{
			Name:                        "WarmTechniqueIsRevertedWithForce",
			TechniqueState:              domain.AttackTechniqueStatusWarm,
			Force:                       true,
			ExpectDidCallRevertFunction: true,
			ExpectDidChangeStateToWarm:  true,
			ExpectError:                 false,
		},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			state := new(statemocks.StateManager)
			state.On("GetRootDirectory").Return("/root")
			state.On("ExtractTechnique").Return(nil)
			state.On("GetTerraformOutputs").Return(map[string]string{"foo": "bar"}, nil)
			state.On("GetTechniqueState", mock.Anything).Return(scenario[i].TechniqueState)
			state.On("SetTechniqueState", mock.Anything).Return(nil)

			var wasReverted = false
			runner := Runner{
				Technique: &domain.AttackTechnique{
					ID:       "foo",
					Detonate: func(domain.ProvidersFactory, map[string]string) error { return nil },
					Revert: func(factory domain.ProvidersFactory, params map[string]string) error {
						wasReverted = true
						return nil
					},
				},
				ShouldForce:  scenario[i].Force,
				StateManager: state,
			}
			runner.Initialize()

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
				state.AssertCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusWarm))
			} else {
				state.AssertNotCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusWarm))
			}
		})
	}

}

func TestRunnerCleanup(t *testing.T) {
	type RunnerCleanupTestScenario struct {
		Name                  string
		Technique             *domain.AttackTechnique
		ShouldForce           bool
		InitialTechniqueState domain.AttackTechniqueState
		TerraformDestroyFails bool
		RevertFails           bool
		// results
		CheckExpectations func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error)
	}

	var scenario = []RunnerCleanupTestScenario{
		{
			Name:                  "Cleaning up an already cold technique without force flag",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: domain.AttackTechniqueStatusCold,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.NotNil(t, err)
				terraform.AssertNotCalled(t, "TerraformDestroy")
				state.AssertNotCalled(t, "CleanupTechnique")
			},
		},
		{

			Name:                  "Cleaning up an already cold technique with force flag",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: domain.AttackTechniqueStatusCold,
			ShouldForce:           true,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.Nil(t, err)
				terraform.AssertCalled(t, "TerraformDestroy", mock.Anything)
				state.AssertCalled(t, "CleanupTechnique")
			},
		},
		{
			Name:                  "Cleaning up a WARM technique",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: domain.AttackTechniqueStatusWarm,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.Nil(t, err)
				terraform.AssertCalled(t, "TerraformDestroy", mock.Anything)
				state.AssertCalled(t, "CleanupTechnique")
				state.AssertCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusCold))
			},
		},
		{
			Name:                  "Cleaning up a DETONATED technique and terraform destroy fails",
			Technique:             &domain.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo)")},
			InitialTechniqueState: domain.AttackTechniqueStatusDetonated,
			TerraformDestroyFails: true,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.NotNil(t, err, "terraform destroy error should be propagated")

				// The technique should not have been marked as properly cleaned up
				state.AssertNotCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusCold))
			},
		},
		{
			Name:                  "Cleaning up a DETONATED technique and revert fails",
			Technique:             &domain.AttackTechnique{ID: "foo"},
			InitialTechniqueState: domain.AttackTechniqueStatusDetonated,
			RevertFails:           true,
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, err error) {
				assert.NotNil(t, err, "revert error should be propagated")

				// The technique should not have been marked as properly cleaned up
				state.AssertNotCalled(t, "SetTechniqueState", domain.AttackTechniqueState(domain.AttackTechniqueStatusCold))
			},
		},
	}

	for i := range scenario {
		state := new(statemocks.StateManager)
		terraform := new(mocks.TerraformManager)

		state.On("GetRootDirectory").Return("/root")
		state.On("ExtractTechnique").Return(nil)
		state.On("GetTechniqueState", mock.Anything).Return(scenario[i].InitialTechniqueState, nil)
		state.On("SetTechniqueState", mock.Anything).Return(nil)
		state.On("CleanupTechnique").Return(nil)
		state.On("GetTerraformOutputs").Return(map[string]string{}, nil)
		if scenario[i].TerraformDestroyFails {
			terraform.On("TerraformDestroy", mock.Anything).Return(errors.New("nope"))
		} else {
			terraform.On("TerraformDestroy", mock.Anything).Return(nil)
		}
		if scenario[i].RevertFails {
			scenario[i].Technique.Revert = func(domain.ProvidersFactory, map[string]string) error {
				return errors.New("nope")
			}
		}
		runner := Runner{
			Technique:        scenario[i].Technique,
			ShouldForce:      scenario[i].ShouldForce,
			TerraformManager: terraform,
			StateManager:     state,
		}
		runner.Initialize()
		err := runner.CleanUp()
		t.Run(scenario[i].Name, func(t *testing.T) { scenario[i].CheckExpectations(t, terraform, state, err) })
	}
}
