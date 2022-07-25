package stratus

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/domain"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistryFilteringByName(t *testing.T) {
	registry := NewRegistry()
	technique := domain.AttackTechnique{ID: "foo"}
	registry.RegisterAttackTechnique(&technique)

	assert.NotNil(t, registry.GetAttackTechniqueByName(technique.ID))
	assert.Nil(t, registry.GetAttackTechniqueByName("nope"), 0)
}

func TestRegistryFiltering(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAttackTechnique(&domain.AttackTechnique{ID: "foo", Platform: domain.AWS, MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence}})
	registry.RegisterAttackTechnique(&domain.AttackTechnique{ID: "bar", Platform: domain.AWS})
	registry.RegisterAttackTechnique(&domain.AttackTechnique{ID: "baz", Platform: domain.Kubernetes, MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation}})

	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Platform: domain.AWS}), 2)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Platform: domain.Kubernetes}), 1)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.Persistence}), 1)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.Execution}), 0)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.PrivilegeEscalation}), 1)
}
