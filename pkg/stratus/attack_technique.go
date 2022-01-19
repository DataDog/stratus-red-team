package stratus

import (
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

type AttackTechnique struct {
	ID                         string
	FriendlyName               string
	Description                string
	MitreAttackTactics         []mitreattack.Tactic
	Platform                   Platform
	Detonate                   func(params map[string]string) error
	Revert                     func(params map[string]string) error
	PrerequisitesTerraformCode []byte
}

func (m AttackTechnique) String() string {
	return m.ID
}
