package runner

import (
	"github.com/datadog/stratus-red-team/internal/runner/mocks"
	statemocks "github.com/datadog/stratus-red-team/internal/state/mocks"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestRunnerWarmUp(t *testing.T) {

	type RunnerWarmupTestScenario struct {
		Name                  string
		Technique             *stratus.AttackTechnique
		ShouldForce           bool
		InitialTechniqueState stratus.AttackTechniqueState
		TerraformOutputs      map[string]string
		PersistedOutputs      map[string]string
		// results
		CheckExpectations func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error)
	}

	var scenario = []RunnerWarmupTestScenario{
		{
			Name:                  "Warming up a technique without pre-requisite Terraform code",
			Technique:             &stratus.AttackTechnique{ID: "foo"},
			InitialTechniqueState: stratus.AttackTechniqueCold,
			PersistedOutputs:      map[string]string{"myoutput": "foo"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				terraform.AssertNotCalled(t, "TerraformInitAndApply")
				state.AssertNotCalled(t, "ExtractTechniqueTerraformFile")
				assert.Nil(t, err)

				// No pre-requisite Terraform code implies there cannot be any output
				assert.Len(t, outputs, 0)
			},
		},
		{
			Name:                  "Warming up a COLD technique",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("foo")},
			InitialTechniqueState: stratus.AttackTechniqueCold,
			TerraformOutputs:      map[string]string{"myoutput": "new"},
			CheckExpectations: func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error) {
				state.AssertCalled(t, "ExtractTechniqueTerraformFile")
				terraform.AssertCalled(t, "TerraformInitAndApply", "/root/foo")
				state.AssertCalled(t, "WriteTerraformOutputs", map[string]string{"myoutput": "new"})
				state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueWarm))

				assert.Nil(t, err)
				assert.Len(t, outputs, 1)
				assert.Equal(t, "new", outputs["myoutput"])
			},
		},
		{
			Name:                  "Warming up a WARM technique without force flag",
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: stratus.AttackTechniqueWarm,
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
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			ShouldForce:           true,
			InitialTechniqueState: stratus.AttackTechniqueWarm,
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
			Technique:             &stratus.AttackTechnique{ID: "foo", PrerequisitesTerraformCode: []byte("bar")},
			InitialTechniqueState: stratus.AttackTechniqueDetonated,
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
		state.On("ExtractTechniqueTerraformFile").Return(nil)
		state.On("GetTechniqueState", mock.Anything).Return(stratus.AttackTechniqueState(scenario[i].InitialTechniqueState), nil)
		state.On("GetTechniqueOutputs").Return(scenario[i].PersistedOutputs, nil)
		terraform.On("TerraformInitAndApply", mock.Anything).Return(scenario[i].TerraformOutputs, nil)
		state.On("WriteTerraformOutputs", mock.Anything).Return(nil)
		state.On("SetTechniqueState", mock.Anything).Return(nil)

		runner := Runner{
			Technique:        scenario[i].Technique,
			ShouldWarmUp:     true,
			ShouldForce:      scenario[i].ShouldForce,
			TerraformManager: terraform,
			StateManager:     state,
		}
		runner.initialize()
		outputs, err := runner.WarmUp()
		t.Run(scenario[i].Name, func(t *testing.T) { scenario[i].CheckExpectations(t, terraform, state, outputs, err) })
	}
}

func TestRunnerDetonate(t *testing.T) {
	state := new(statemocks.StateManager)
	terraform := new(mocks.TerraformManager)

	state.On("GetRootDirectory").Return("/root")
	state.On("ExtractTechniqueTerraformFile").Return(nil)
	state.On("GetTechniqueState", mock.Anything).Return(stratus.AttackTechniqueState(stratus.AttackTechniqueWarm), nil)
	terraform.On("TerraformInitAndApply", mock.Anything).Return(map[string]string{}, nil)
	state.On("WriteTerraformOutputs", mock.Anything).Return(nil)
	state.On("SetTechniqueState", mock.Anything).Return(nil)

	var wasDetonated bool = false
	runner := Runner{
		Technique: &stratus.AttackTechnique{
			ID: "foo",
			Detonate: func(map[string]string) error {
				wasDetonated = true
				return nil
			},
		},
		ShouldWarmUp:     true,
		TerraformManager: terraform,
		StateManager:     state,
	}
	runner.initialize()
	err := runner.Detonate()

	assert.Nil(t, err)
	assert.True(t, wasDetonated)
	state.AssertCalled(t, "SetTechniqueState", stratus.AttackTechniqueState(stratus.AttackTechniqueDetonated))
}

func TestRunnerCleanup(t *testing.T) {
	type RunnerCleanupTestScenario struct {
		Name                  string
		Technique             *stratus.AttackTechnique
		ShouldForce           bool
		InitialTechniqueState stratus.AttackTechniqueState
		// results
		CheckExpectations func(t *testing.T, terraform *mocks.TerraformManager, state *statemocks.StateManager, outputs map[string]string, err error)
	}
}
