package config

import (
	"log"
	"maps"

	"github.com/spf13/viper"
	v1 "k8s.io/api/core/v1"
)

// KubernetesConfig holds Kubernetes-specific configuration
type KubernetesConfig interface {
	GetTechniquePodConfig(techniqueID string, vars SubstitutionVars) K8sPodConfig
}

type KubernetesConfigImpl struct {
	v *viper.Viper
}

var _ KubernetesConfig = &KubernetesConfigImpl{}

// populateViperOverride creates a kubernetes config object from a source viper config.
// It deep-merges the default settings with technique-specific overrides. Technique values
// take precedence, but unset keys fall through to the default. Template variables
// (e.g. %%correlation_id%%) in string values are substituted before the result is stored.
func (k *KubernetesConfigImpl) populateViperOverride(src *viper.Viper, dst *viper.Viper, techniqueID string, vars SubstitutionVars) {
	defaultRaw := src.Get("kubernetes" + keyDelimiter + "default")
	if defaultRaw == nil {
		return
	}

	merged := toStringMap(defaultRaw)
	if techniqueRaw := src.Get("kubernetes" + keyDelimiter + "techniques" + keyDelimiter + techniqueID); techniqueRaw != nil {
		deepMerge(merged, toStringMap(techniqueRaw))
	}

	dst.Set("kubernetes", substituteMap(merged, vars))
}

// deepMerge recursively merges src into dst. Values in src take precedence.
// Maps are merged recursively; all other types are replaced.
func deepMerge(dst, src map[string]any) {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}

		dstMap, dstIsMap := dstVal.(map[string]any)
		srcMap, srcIsMap := srcVal.(map[string]any)
		if dstIsMap && srcIsMap {
			deepMerge(dstMap, srcMap)
		} else {
			dst[key] = srcVal
		}
	}
}

// toStringMap converts a value to map[string]any. Returns an empty map if the
// conversion fails (e.g. the value is nil or not a map).
func toStringMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return make(map[string]any)
}

// GetTechniquePodConfig returns the merged pod configuration for a specific technique,
// with template variables (e.g. %%correlation_id%%) substituted from vars.
func (k *KubernetesConfigImpl) GetTechniquePodConfig(techniqueID string, vars SubstitutionVars) K8sPodConfig {
	if k == nil || k.v == nil {
		return K8sPodConfig{}
	}
	merged := newViper()
	k.populateViperOverride(k.v, merged, techniqueID, vars)

	var podConfig K8sPodConfig
	if sub := merged.Sub("kubernetes" + keyDelimiter + "pod"); sub != nil {
		if err := sub.Unmarshal(&podConfig); err != nil {
			log.Println("unable to unmarshal pod config: " + err.Error())
		}
	}
	return podConfig
}

// K8sPodConfig holds pod-level configuration that can be applied to k8s pods.
type K8sPodConfig struct {
	Image       string            `yaml:"image"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
	Tolerations []v1.Toleration   `yaml:"tolerations"`
	NodeSelector    map[string]string   `yaml:"node_selector"`
	SecurityContext *v1.SecurityContext `yaml:"security_context"`
}

// ApplyToPod applies the configuration to a pod spec, modifying it in place.
func (c *K8sPodConfig) ApplyToPod(pod *v1.Pod) {
	if c == nil {
		return
	}

	if c.Image != "" && len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].Image = c.Image
	}

	if len(c.Labels) > 0 {
		if pod.ObjectMeta.Labels == nil {
			pod.ObjectMeta.Labels = make(map[string]string)
		}
		maps.Copy(pod.ObjectMeta.Labels, c.Labels)
	}

	if len(c.Annotations) > 0 {
		if pod.ObjectMeta.Annotations == nil {
			pod.ObjectMeta.Annotations = make(map[string]string)
		}
		maps.Copy(pod.ObjectMeta.Annotations, c.Annotations)
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
