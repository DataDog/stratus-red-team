package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestGetTechniquePodConfig(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		techniqueID string
		expected    K8sPodConfig
	}{
		{
			name: "default-tolerations-applied",
			yaml: `
kubernetes:
  default:
    pod:
      tolerations:
        - key: dedicated
          operator: Equal
          value: security
          effect: NoSchedule
`,
			techniqueID: "k8s.privilege-escalation.privileged-pod",
			expected: K8sPodConfig{
				Tolerations: []v1.Toleration{{
					Key:      "dedicated",
					Operator: v1.TolerationOpEqual,
					Value:    "security",
					Effect:   v1.TaintEffectNoSchedule,
				}},
			},
		},
		{
			name: "default-image-and-labels",
			yaml: `
kubernetes:
  default:
    pod:
      image: custom:latest
      labels:
        app: stratus
`,
			techniqueID: "k8s.privilege-escalation.privileged-pod",
			expected: K8sPodConfig{
				Image:  "custom:latest",
				Labels: map[string]string{"app": "stratus"},
			},
		},
		{
			name: "annotations-merge-with-technique-override",
			yaml: `
kubernetes:
  default:
    pod:
      annotations:
        app.kubernetes.io/name: stratus
        app.kubernetes.io/managed-by: default
  techniques:
    "k8s.test.technique":
      pod:
        annotations:
          app.kubernetes.io/managed-by: technique
`,
			techniqueID: "k8s.test.technique",
			expected: K8sPodConfig{
				Annotations: map[string]string{
					"app.kubernetes.io/name":       "stratus",
					"app.kubernetes.io/managed-by": "technique",
				},
			},
		},
		{
			name: "technique-override-merges-with-default",
			yaml: `
kubernetes:
  default:
    namespace: default-ns
    pod:
      image: default-image
      labels:
        app: stratus
      tolerations:
        - key: dedicated
          operator: Equal
          value: security
          effect: NoSchedule
  techniques:
    "k8s.test.technique":
      pod:
        image: override-image
`,
			techniqueID: "k8s.test.technique",
			expected: K8sPodConfig{
				Image:  "override-image",
				Labels: map[string]string{"app": "stratus"},
				Tolerations: []v1.Toleration{{
					Key:      "dedicated",
					Operator: v1.TolerationOpEqual,
					Value:    "security",
					Effect:   v1.TaintEffectNoSchedule,
				}},
			},
		},
		{
			name:        "no-config",
			yaml:        ``,
			techniqueID: "k8s.test.technique",
			expected:    K8sPodConfig{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig(tc.yaml)
			actual := cfg.GetKubernetesConfig().GetTechniquePodConfig(tc.techniqueID, SubstitutionVars{})
			assert.Equal(t, tc.expected, actual)
		})
	}
}

// TestGetTechniquePodConfig_TemplateSubstitution verifies that %%correlation_id%%
// is resolved end-to-end (YAML → merged map → unmarshaled struct), that unknown
// template variables (e.g. Datadog Agent's %%kube_namespace%%) survive untouched
// for downstream resolution, and that substitution applies to any string value
// not just annotations.
func TestGetTechniquePodConfig_TemplateSubstitution(t *testing.T) {
	yaml := `
kubernetes:
  default:
    namespace: stratus-%%correlation_id%%
    pod:
      image: registry/img:%%correlation_id%%
      labels:
        team: red
      annotations:
        ad.datadoghq.com/tags: '{"detonation_id":"%%correlation_id%%","ns":"%%kube_namespace%%"}'
`
	cfg := newTestConfig(yaml)
	vars := SubstitutionVars{CorrelationID: "abc-123"}
	actual := cfg.GetKubernetesConfig().GetTechniquePodConfig("k8s.any.technique", vars)

	assert.Equal(t, "registry/img:abc-123", actual.Image, "substitution applies to image")
	assert.Equal(t, map[string]string{"team": "red"}, actual.Labels, "label without template untouched")
	assert.Equal(t,
		`{"detonation_id":"abc-123","ns":"%%kube_namespace%%"}`,
		actual.Annotations["ad.datadoghq.com/tags"],
		"correlation_id substituted, kube_namespace passed through for DD agent")
}
