package config

import (
	"encoding/json"
	"log"
	"maps"

	v1 "k8s.io/api/core/v1"
)

// KubernetesConfig holds Kubernetes-specific configuration
type KubernetesConfig interface {
	GetTechniquePodConfig(techniqueID string) K8sPodConfig
	GetTerraformVariables(techniqueID string, overrides []TerraformConfigVariable) map[string]string
}

type KubernetesConfigImpl struct {
	// Namespace is the default namespace for k8s techniques
	Namespace string `yaml:"namespace"`

	// Defaults are applied to all k8s pods unless overridden per-technique
	Defaults K8sPodConfig `yaml:"defaults"`

	// Techniques contains per-technique configuration overrides
	// Key is the technique ID (e.g., "k8s.privilege-escalation.privileged-pod")
	Techniques map[string]K8sPodConfig `yaml:"techniques"`
}

var _ KubernetesConfig = &KubernetesConfigImpl{}

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

// GetTechniquePodConfig returns the merged Pod configuration for a specific technique.
func (k *KubernetesConfigImpl) GetTechniquePodConfig(techniqueID string) K8sPodConfig {
	if k == nil {
		return K8sPodConfig{}
	}

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
	if c == nil {
		return
	}

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

type KubernetesVariablesNames struct {
	Namespace TerraformConfigVariable

	Image           TerraformConfigVariable
	Labels          TerraformConfigVariable
	Tolerations     TerraformConfigVariable
	NodeSelector    TerraformConfigVariable
	SecurityContext TerraformConfigVariable
}

var KubernetesVariables = KubernetesVariablesNames{
	Namespace: TerraformConfigVariable("namespace"),

	Image:           TerraformConfigVariable("image"),
	Labels:          TerraformConfigVariable("labels"),
	Tolerations:     TerraformConfigVariable("tolerations"),
	NodeSelector:    TerraformConfigVariable("node_selector"),
	SecurityContext: TerraformConfigVariable("security_context"),
}

func (c *KubernetesConfigImpl) GetTerraformVariables(techniqueID string, overrides []TerraformConfigVariable) map[string]string {
	if c == nil {
		return nil
	}

	techniqueConfig := c.GetTechniquePodConfig(techniqueID)

	// Get all available variables from the pod config
	allVars := techniqueConfig.ToTerraformVariables()
	if allVars == nil {
		allVars = make(map[string]string)
	}

	// Add namespace (lives at KubernetesConfig level, not K8sPodConfig)
	if c.Namespace != "" {
		allVars[string(KubernetesVariables.Namespace)] = c.Namespace
	}

	// Filter to only the requested variables
	return FilterVariables(allVars, overrides)
}

// ToTerraformVariables converts the config to Terraform variables.
func (c *K8sPodConfig) ToTerraformVariables() map[string]string {
	if c == nil {
		return nil
	}

	vars := make(map[string]string)

	if c.Image != "" {
		vars[string(KubernetesVariables.Image)] = c.Image
	}

	if len(c.Labels) > 0 {
		labelsJSON, err := json.Marshal(c.Labels)
		if err != nil {
			log.Println("Error marshalling config labels to terraform variables - They will be ignored: " + err.Error())
		} else {
			vars[string(KubernetesVariables.Labels)] = string(labelsJSON)
		}
	}

	if len(c.Tolerations) > 0 {
		tolerationsJSON, err := marshalTolerations(c.Tolerations)
		if err != nil {
			log.Println("Error marshalling config tolerations to terraform variables - They will be ignored: " + err.Error())
		} else {
			vars[string(KubernetesVariables.Tolerations)] = string(tolerationsJSON)
		}
	}

	if len(c.NodeSelector) > 0 {
		nodeSelectorJSON, err := json.Marshal(c.NodeSelector)
		if err != nil {
			log.Println("Error marshalling config node selector to terraform variables - They will be ignored: " + err.Error())
		} else {
			vars[string(KubernetesVariables.NodeSelector)] = string(nodeSelectorJSON)
		}
	}

	if c.SecurityContext != nil {
		securityContextJSON, err := json.Marshal(c.SecurityContext)
		if err != nil {
			log.Println("Error marshalling config security context to terraform variables - It will be ignored: " + err.Error())
		} else {
			vars[string(KubernetesVariables.SecurityContext)] = string(securityContextJSON)
		}
	}

	if len(vars) == 0 {
		return nil
	}
	return vars
}

func marshalTolerations(tolerations []v1.Toleration) ([]byte, error) {
	// Convert to simplified format for Terraform
	type simpleToleration struct {
		Key      string `json:"key"`
		Operator string `json:"operator"`
		Value    string `json:"value"`
		Effect   string `json:"effect"`
	}
	simplified := make([]simpleToleration, len(tolerations))
	for i, t := range tolerations {
		simplified[i] = simpleToleration{
			Key:      t.Key,
			Operator: string(t.Operator),
			Value:    t.Value,
			Effect:   string(t.Effect),
		}
	}
	return json.Marshal(simplified)
}
