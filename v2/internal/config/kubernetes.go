package config

import (
	"encoding/json"

	v1 "k8s.io/api/core/v1"
)

// KubernetesConfig holds Kubernetes-specific configuration
type KubernetesConfig struct {
	// Namespace is the default namespace for k8s techniques (overridable by --namespace CLI flag)
	Namespace string `yaml:"namespace"`

	// Defaults are applied to all k8s pods unless overridden per-technique
	Defaults K8sPodConfig `yaml:"defaults"`

	// Techniques contains per-technique configuration overrides
	// Key is the technique ID (e.g., "k8s.privilege-escalation.privileged-pod")
	Techniques map[string]K8sPodConfig `yaml:"techniques"`
}

// K8sPodConfig holds pod-level configuration that can be applied to k8s pods
type K8sPodConfig struct {
	// Image overrides the container image (applies to first container)
	Image string `yaml:"image"`

	// Tolerations to apply to the pod
	Tolerations []v1.Toleration `yaml:"tolerations"`

	// NodeSelector to apply to the pod
	NodeSelector map[string]string `yaml:"nodeSelector"`

	// SecurityContext overrides for the first container
	SecurityContext *v1.SecurityContext `yaml:"securityContext"`

	// TerraformVariables indicates that pod config (image, tolerations, nodeSelector)
	// should be passed to Terraform as variables instead of being applied via ApplyPodConfig().
	// Use this for techniques that create pods via Terraform rather than Go code.
	TerraformVariables bool `yaml:"terraformVariables"`
}

// GetTechniqueConfig returns the merged configuration for a specific technique.
// It merges defaults with technique-specific overrides (technique config takes precedence).
func (k *KubernetesConfig) GetTechniqueConfig(techniqueID string) K8sPodConfig {
	result := k.Defaults

	if techniqueConfig, exists := k.Techniques[techniqueID]; exists {
		// Override with technique-specific values (non-zero values take precedence)
		if techniqueConfig.Image != "" {
			result.Image = techniqueConfig.Image
		}
		if len(techniqueConfig.Tolerations) > 0 {
			result.Tolerations = techniqueConfig.Tolerations
		}
		if len(techniqueConfig.NodeSelector) > 0 {
			result.NodeSelector = techniqueConfig.NodeSelector
		}
		if techniqueConfig.SecurityContext != nil {
			result.SecurityContext = techniqueConfig.SecurityContext
		}
		// TerraformVariables is per-technique only, not inherited from defaults
		result.TerraformVariables = techniqueConfig.TerraformVariables
	}

	return result
}

// ApplyToPod applies the configuration to a pod spec, modifying it in place.
func (c *K8sPodConfig) ApplyToPod(pod *v1.Pod) {
	// Apply image override to first container
	if c.Image != "" && len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].Image = c.Image
	}

	// Apply tolerations
	if len(c.Tolerations) > 0 {
		pod.Spec.Tolerations = c.Tolerations
	}

	// Apply node selector
	if len(c.NodeSelector) > 0 {
		pod.Spec.NodeSelector = c.NodeSelector
	}

	// Apply security context to first container
	if c.SecurityContext != nil && len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].SecurityContext = c.SecurityContext
	}
}

// ToTerraformVariables converts the config to Terraform variables for k8s techniques
// that create pods via Terraform. Returns nil if no config values are set.
func (c *K8sPodConfig) ToTerraformVariables() map[string]string {
	vars := make(map[string]string)

	if c.Image != "" {
		vars["image"] = c.Image
	}

	if len(c.Tolerations) > 0 {
		// Convert to simplified format for Terraform
		type simpleToleration struct {
			Key      string `json:"key"`
			Operator string `json:"operator"`
			Value    string `json:"value"`
			Effect   string `json:"effect"`
		}
		simplified := make([]simpleToleration, len(c.Tolerations))
		for i, t := range c.Tolerations {
			simplified[i] = simpleToleration{
				Key:      t.Key,
				Operator: string(t.Operator),
				Value:    t.Value,
				Effect:   string(t.Effect),
			}
		}
		tolerationsJSON, err := json.Marshal(simplified)
		if err == nil {
			vars["tolerations"] = string(tolerationsJSON)
		}
	}

	if len(c.NodeSelector) > 0 {
		nodeSelectorJSON, err := json.Marshal(c.NodeSelector)
		if err == nil {
			vars["node_selector"] = string(nodeSelectorJSON)
		}
	}

	if len(vars) == 0 {
		return nil
	}
	return vars
}
