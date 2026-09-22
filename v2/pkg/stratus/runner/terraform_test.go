package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTerraformEnvironmentPreservesEmptyPluginCacheDirectory(t *testing.T) {
	t.Setenv(pluginCacheEnvVar, "")

	env := (&TerraformManagerImpl{}).terraformEnvironment()
	cacheDirectory, isSet := env[pluginCacheEnvVar]

	assert.True(t, isSet)
	assert.Empty(t, cacheDirectory)
}
