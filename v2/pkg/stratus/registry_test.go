package stratus

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistryFilteringByName(t *testing.T) {
	registry := NewRegistry()
	technique := AttackTechnique{ID: "foo"}
	registry.RegisterAttackTechnique(&technique)

	assert.NotNil(t, registry.GetAttackTechniqueByName(technique.ID))
	assert.Nil(t, registry.GetAttackTechniqueByName("nope"), 0)
}

func TestRegistryFiltering(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAttackTechnique(&AttackTechnique{ID: "foo", Platform: AWS, MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence}})
	registry.RegisterAttackTechnique(&AttackTechnique{ID: "bar", Platform: AWS})
	registry.RegisterAttackTechnique(&AttackTechnique{ID: "baz", Platform: Kubernetes, MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation}})

	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Platform: AWS}), 2)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Platform: Kubernetes}), 1)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.Persistence}), 1)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.Execution}), 0)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.PrivilegeEscalation}), 1)
}
