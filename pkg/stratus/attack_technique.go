package stratus

import (
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

type AttackTechnique struct {
	Name                       string
	Description                string
	MitreAttackTactics         []mitreattack.Tactic
	Platform                   Platform
	Detonate                   func(terraformOutputs map[string]string) error
	Cleanup                    func() error
	PrerequisitesTerraformCode []byte
}

func (m AttackTechnique) String() string {
	return m.Name
}
