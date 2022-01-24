package stratus

import (
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

type AttackTechnique struct {
	// Short identifier, e.g. aws.persistence.create-iam-user
	ID string

	// Friendly-looking short name
	FriendlyName string

	// Full description (multi-line)
	Description string

	// Indicates if the technique is expected to be slow to warm-up or detonate
	IsSlow bool

	// MITRE ATT&CK Tactics to which this technique maps
	// see https://attack.mitre.org/techniques/enterprise/
	MitreAttackTactics []mitreattack.Tactic

	// The platform of the technique, e.g. AWS
	Platform Platform

	// Terraform code to apply to create the necessary pre-requisites for the technique to be detonated
	PrerequisitesTerraformCode []byte

	// Detonation function
	// Parameters are the Terraform outputs
	Detonate func(params map[string]string) error

	// Indicates if the detonation function is idempotent, i.e. if it can be run multiple times without reverting it
	IsIdempotent bool

	// Reversion function, to revert the side effects of a detonation
	Revert func(params map[string]string) error
}

func (m AttackTechnique) String() string {
	return m.ID
}
