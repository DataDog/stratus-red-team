package main

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

type index struct {
	techniques []*stratus.AttackTechnique
	values     map[stratus.Platform]map[string][]*stratus.AttackTechnique
}

func NewIndex(techniques []*stratus.AttackTechnique) index {
	return index{techniques: techniques, values: make(map[stratus.Platform]map[string][]*stratus.AttackTechnique)}
}

func (i index) Values() map[stratus.Platform]map[string][]*stratus.AttackTechnique {
	i.values = map[stratus.Platform]map[string][]*stratus.AttackTechnique{}

	for j := range i.techniques {
		technique := i.techniques[j]
		for j := range technique.MitreAttackTactics {
			tactic := mitreattack.AttackTacticToString(technique.MitreAttackTactics[j])
			if i.values[technique.Platform] == nil {
				i.values[technique.Platform] = make(map[string][]*stratus.AttackTechnique)
			}
			if i.values[technique.Platform][tactic] == nil {
				i.values[technique.Platform][tactic] = make([]*stratus.AttackTechnique, 0)
			}
			i.values[technique.Platform][tactic] = append(i.values[technique.Platform][tactic], technique)
		}
	}

	return i.values
}
