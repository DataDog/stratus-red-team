package stratus

import (
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

var registry Registry

func init() {
	registry = NewRegistry()
}

func GetRegistry() *Registry {
	return &registry
}

type Registry struct {
	techniques []*AttackTechnique
}

func NewRegistry() Registry {
	return Registry{techniques: []*AttackTechnique{}}
}

func (m *Registry) RegisterAttackTechnique(technique *AttackTechnique) {
	m.techniques = append(m.techniques, technique)
}

func (m *Registry) GetAttackTechniqueByName(name string) *AttackTechnique {
	for i := range m.techniques {
		if m.techniques[i].Name == name {
			return m.techniques[i]
		}
	}

	return nil
}

func (m *Registry) GetAttackTechniques(filter *AttackTechniqueFilter) []*AttackTechnique {
	var ret = []*AttackTechnique{}

	for i := range m.techniques {
		technique := m.techniques[i]
		if filter.matches(technique) {
			ret = append(ret, technique)
		}
	}

	return ret
}

func (m *Registry) ListAttackTechniques() []*AttackTechnique {
	return m.techniques
}

type AttackTechniqueFilter struct {
	Platform Platform
	Tactic   mitreattack.Tactic
}

func (m *AttackTechniqueFilter) matches(technique *AttackTechnique) bool {
	var platformMatches = false
	var mitreAttackTacticMatches = false

	if m.Platform == "" || technique.Platform == m.Platform {
		platformMatches = true
	}

	if m.Tactic == "" {
		mitreAttackTacticMatches = true
	} else {
		for i := range technique.MitreAttackTactics {
			if technique.MitreAttackTactics[i] == m.Tactic {
				mitreAttackTacticMatches = true
				break
			}
		}
	}

	return platformMatches && mitreAttackTacticMatches
}
