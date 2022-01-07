package registrations

import (
	"github.com/datadog/stratus-red-team/pkg/attacktechnique"
)

//TODO: use pointers
var techniques []attacktechnique.AttackTechnique

func RegisterAttackTechnique(technique attacktechnique.AttackTechnique) {
	techniques = append(techniques, technique)
}

func ListAttackTechniques() []attacktechnique.AttackTechnique {
	return techniques
}

func GetAttackTechniqueByName(name string) *attacktechnique.AttackTechnique {
	for i := range techniques {
		if techniques[i].Name == name {
			return &techniques[i]
		}
	}

	return nil
}

func GetAttackTechniquesForPlatform(platform string) []attacktechnique.AttackTechnique {
	var ret = []attacktechnique.AttackTechnique{}
	for i := range techniques {
		if technique := techniques[i]; technique.Platform == platform {
			ret = append(ret, technique)
		}
	}

	return ret
}
