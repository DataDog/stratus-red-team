package stratus

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

func GetAttackTechniquesForPlatform(platform Platform) []*AttackTechnique {
	var ret = []*AttackTechnique{}
	for i := range techniques {
		if technique := techniques[i]; technique.Platform == platform {
			ret = append(ret, technique)
		}
	}

	return ret
}
