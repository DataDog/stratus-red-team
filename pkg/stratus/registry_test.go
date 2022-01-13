package stratus

import (
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRegistryFilteringByName(t *testing.T) {
	registry := NewRegistry()
	technique := AttackTechnique{Name: "foo"}
	registry.RegisterAttackTechnique(&technique)

	assert.NotNil(t, registry.GetAttackTechniqueByName(technique.Name))
	assert.Nil(t, registry.GetAttackTechniqueByName("nope"), 0)
}

func TestRegistryFiltering(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAttackTechnique(&AttackTechnique{Name: "foo", Platform: AWS, MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence}})
	registry.RegisterAttackTechnique(&AttackTechnique{Name: "bar", Platform: AWS})

	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Platform: AWS}), 2)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.Persistence}), 1)
	assert.Len(t, registry.GetAttackTechniques(&AttackTechniqueFilter{Tactic: mitreattack.Execution}), 0)
}
