package attacktechnique

/*
Each attack technique has:
- A warmup phase to spin up pre-requisite infrastructure and configuration (declarative)
- An imperative "detonation" phase (which should clean up)
- A tear down phase
*/
type AttackTechnique struct {
	Name                       string
	Description                string
	Platform                   string
	Detonate                   func(terraformOutputs map[string]string) error
	Cleanup                    func() error
	PrerequisitesTerraformCode []byte
}

func (m AttackTechnique) String() string {
	return m.Name
}
