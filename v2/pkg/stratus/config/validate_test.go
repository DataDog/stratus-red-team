package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantError bool
	}{
		{
			name:      "empty-config",
			yaml:      ``,
			wantError: false,
		},
		{
			name: "valid-minimal",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
`,
			wantError: false,
		},
		{
			name: "valid-full",
			yaml: `
kubernetes:
  default:
    namespace: security-testing
    pod:
      image: busybox:latest
      labels:
        app: stratus
      annotations:
        app.kubernetes.io/managed-by: stratus
      tolerations:
        - key: dedicated
          operator: Equal
          value: security
          effect: NoSchedule
      node_selector:
        team: security
      security_context:
        privileged: true
  techniques:
    "k8s.privilege-escalation.privileged-pod":
      pod:
        image: custom.registry.io/custom:latest
    "k8s.privilege-escalation.nodes-proxy":
      pod:
        image: custom.registry.io/custom-2:latest
`,
			wantError: false,
		},
		{
			name: "wrong-type-for-annotations",
			yaml: `
kubernetes:
  default:
    pod:
      annotations: "not-a-map"
`,
			wantError: true,
		},
		{
			name: "unknown-top-level-key",
			yaml: `
kubernetes:
  default:
    namespace: test
typo_key: value
`,
			wantError: true,
		},
		{
			name: "unknown-key-in-kubernetes",
			yaml: `
kubernetes:
  defaults:
    namespace: test
`,
			wantError: true,
		},
		{
			name: "unknown-key-in-pod",
			yaml: `
kubernetes:
  default:
    pod:
      imagee: busybox
`,
			wantError: true,
		},
		{
			name: "wrong-type-for-namespace",
			yaml: `
kubernetes:
  default:
    namespace: 42
`,
			wantError: true,
		},
		{
			name: "wrong-type-for-labels",
			yaml: `
kubernetes:
  default:
    pod:
      labels: "not-a-map"
`,
			wantError: true,
		},
		{
			name: "unknown-key-in-technique-override",
			yaml: `
kubernetes:
  techniques:
    "k8s.tactic.procedure":
      pod:
        img: wrong-key
`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig([]byte(tc.yaml))
			if tc.wantError {
				assert.Error(t, err, "expected validation error")
			} else {
				assert.NoError(t, err, "unexpected validation error")
			}
		})
	}
}

func TestValidateConfig_ErrorMessages(t *testing.T) {
	tests := []struct {
		name            string
		yaml            string
		wantErrContains string
	}{
		{
			name: "typo-in-pod-key",
			yaml: `
kubernetes:
  default:
    pod:
      imagee: busybox
`,
			wantErrContains: "imagee",
		},
		{
			name: "typo-defaults-instead-of-default",
			yaml: `
kubernetes:
  defaults:
    namespace: test
`,
			wantErrContains: "defaults",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig([]byte(tc.yaml))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrContains)
		})
	}
}
