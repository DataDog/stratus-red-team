package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeKubeconfig(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestBuildKubeRestConfig_SingleKubeconfigPath(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := writeKubeconfig(t, dir, "config", `
apiVersion: v1
kind: Config
current-context: ctx-a
clusters:
- name: cluster-a
  cluster:
    server: https://server-a:6443
contexts:
- name: ctx-a
  context:
    cluster: cluster-a
    user: user-a
users:
- name: user-a
  user:
    token: token-a
`)

	t.Setenv("KUBECONFIG", kubeconfig)

	restConfig, err := buildKubeRestConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://server-a:6443", restConfig.Host)
}

// A KUBECONFIG environment variable may contain several ':'-separated paths that
// are merged together, as documented at
// https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/#set-the-kubeconfig-environment-variable
// The current context can then reference a context defined in any of the merged
// files.
func TestBuildKubeRestConfig_MergesMultipleKubeconfigPaths(t *testing.T) {
	dir := t.TempDir()

	// The first file sets the current context to one that is only defined in the
	// second file, so resolution can only succeed if both files are merged.
	first := writeKubeconfig(t, dir, "config-a", `
apiVersion: v1
kind: Config
current-context: ctx-b
clusters:
- name: cluster-a
  cluster:
    server: https://server-a:6443
contexts:
- name: ctx-a
  context:
    cluster: cluster-a
    user: user-a
users:
- name: user-a
  user:
    token: token-a
`)
	second := writeKubeconfig(t, dir, "config-b", `
apiVersion: v1
kind: Config
clusters:
- name: cluster-b
  cluster:
    server: https://server-b:6443
contexts:
- name: ctx-b
  context:
    cluster: cluster-b
    user: user-b
users:
- name: user-b
  user:
    token: token-b
`)

	t.Setenv("KUBECONFIG", first+string(os.PathListSeparator)+second)

	restConfig, err := buildKubeRestConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://server-b:6443", restConfig.Host)
}
