package stratus

import (
	"github.com/datadog/stratus-red-team/internal/mitreattack"
)

/*
Each attack technique has:
- A warmup phase to spin up pre-requisite infrastructure and configuration (declarative)
- An imperative "detonation" phase (which should clean up)
- A tear down phase
*/
type AttackTechnique struct {
	Name                       string
	Description                string
	MitreAttackTechnique       []mitreattack.Tactic
	Platform                   Platform
	Detonate                   func(terraformOutputs map[string]string) error
	Cleanup                    func() error
	PrerequisitesTerraformCode []byte
}

func (m AttackTechnique) String() string {
	return m.Name
}
