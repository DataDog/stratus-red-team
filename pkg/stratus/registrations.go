package stratus

import (
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

var techniques []*AttackTechnique

func RegisterAttackTechnique(technique *AttackTechnique) {
	techniques = append(techniques, technique)
}

func ListAttackTechniques() []*AttackTechnique {
	return techniques
}

func GetAttackTechniqueByName(name string) *AttackTechnique {
	for i := range techniques {
		if techniques[i].Name == name {
			return techniques[i]
		}
	}

	return nil
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

func GetAttackTechniques(filter *AttackTechniqueFilter) []*AttackTechnique {
	var ret = []*AttackTechnique{}

	for i := range techniques {
		technique := techniques[i]
		if filter.matches(technique) {
			ret = append(ret, technique)
		}
	}

	return ret
}
