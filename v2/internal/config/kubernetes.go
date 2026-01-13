package config

import (
	"encoding/json"
	"maps"

	v1 "k8s.io/api/core/v1"
)

// KubernetesConfig holds Kubernetes-specific configuration
type KubernetesConfig struct {
	// Namespace is the default namespace for k8s techniques
	Namespace string `yaml:"namespace"`

	// Defaults are applied to all k8s pods unless overridden per-technique
	Defaults K8sPodConfig `yaml:"defaults"`

	// Techniques contains per-technique configuration overrides
	// Key is the technique ID (e.g., "k8s.privilege-escalation.privileged-pod")
	Techniques map[string]K8sPodConfig `yaml:"techniques"`
}

// K8sPodConfig holds pod-level configuration that can be applied to k8s pods
type K8sPodConfig struct {
	// Image overrides the container image
	Image string `yaml:"image"`

	// Labels to add to the pod metadata
	Labels map[string]string `yaml:"labels"`

	// Tolerations to apply to the pod
	Tolerations []v1.Toleration `yaml:"tolerations"`

	// NodeSelector to apply to the pod
	NodeSelector map[string]string `yaml:"nodeSelector"`

	// SecurityContext overrides
	SecurityContext *v1.SecurityContext `yaml:"securityContext"`
}

// GetTechniqueConfig returns the merged configuration for a specific technique.
func (k *KubernetesConfig) GetTechniqueConfig(techniqueID string) K8sPodConfig {
	result := k.Defaults

	if techniqueConfig, exists := k.Techniques[techniqueID]; exists {
		// Override with technique-specific values (non-zero values take precedence)
		if techniqueConfig.Image != "" {
			result.Image = techniqueConfig.Image
		}
		if len(techniqueConfig.Labels) > 0 {
			result.Labels = techniqueConfig.Labels
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
	}

	return result
}

// ApplyToPod applies the configuration to a pod spec, modifying it in place.
func (c *K8sPodConfig) ApplyToPod(pod *v1.Pod) {
	// Apply image override to first container
	if c.Image != "" && len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].Image = c.Image
	}

	// Merge existing spec with configuration

	if len(c.Labels) > 0 {
		if pod.ObjectMeta.Labels == nil {
			pod.ObjectMeta.Labels = make(map[string]string)
		}
		maps.Copy(pod.ObjectMeta.Labels, c.Labels)
	}

	if len(c.Tolerations) > 0 {
		if pod.Spec.Tolerations == nil {
			pod.Spec.Tolerations = make([]v1.Toleration, 0)
		}
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, c.Tolerations...)
	}

	if len(c.NodeSelector) > 0 {
		if pod.Spec.NodeSelector == nil {
			pod.Spec.NodeSelector = make(map[string]string)
		}
		maps.Copy(pod.Spec.NodeSelector, c.NodeSelector)
	}

	// TODO: Allow merging security context rather than overriding completely.
	if c.SecurityContext != nil && len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].SecurityContext = c.SecurityContext
	}
}

// ToTerraformVariables converts the config to Terraform variables.
func (c *K8sPodConfig) ToTerraformVariables() map[string]string {
	vars := make(map[string]string)

	if c.Image != "" {
		vars["image"] = c.Image
	}

	if len(c.Labels) > 0 {
		labelsJSON, err := json.Marshal(c.Labels)
		if err == nil {
			vars["labels"] = string(labelsJSON)
		}
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
