package registrations

import (
	"github.com/datadog/stratus-red-team/pkg/stratus"
)

var techniques []*stratus.AttackTechnique

func RegisterAttackTechnique(technique *stratus.AttackTechnique) {
	techniques = append(techniques, technique)
}

func ListAttackTechniques() []*stratus.AttackTechnique {
	return techniques
}

func GetAttackTechniqueByName(name string) *stratus.AttackTechnique {
	for i := range techniques {
		if techniques[i].Name == name {
			return techniques[i]
		}
	}

	return nil
}

func GetAttackTechniquesForPlatform(platform stratus.Platform) []*stratus.AttackTechnique {
	var ret = []*stratus.AttackTechnique{}
	for i := range techniques {
		if technique := techniques[i]; technique.Platform == platform {
			ret = append(ret, technique)
		}
	}

	return ret
}
