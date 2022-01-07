package aws

import (
	"github.com/datadog/stratus-red-team/internal/registrations"
	"github.com/datadog/stratus-red-team/pkg/attacktechnique"
)

func init() {
	registrations.RegisterAttackTechnique(attacktechnique.AttackTechnique{
		Name:     "aws_create-backdoor-role",
		Platform: "aws",
	})
}
