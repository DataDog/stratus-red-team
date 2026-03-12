package config

import (
	"log"
	"maps"

	"github.com/spf13/viper"
	v1 "k8s.io/api/core/v1"
)

// KubernetesConfig holds Kubernetes-specific configuration
type KubernetesConfig interface {
	GetTechniquePodConfig(techniqueID string) K8sPodConfig
}

type KubernetesConfigImpl struct {
	v *viper.Viper
}

var _ KubernetesConfig = &KubernetesConfigImpl{}

// populateViperOverride creates a kubernetes config object from a source viper config.
// It picks the default settings and overrides them with the technique-specific values, if they exist.
func (k *KubernetesConfigImpl) populateViperOverride(src *viper.Viper, dst *viper.Viper, techniqueID string) {
	dst.SetDefault("kubernetes", src.Get("kubernetes.default"))
	if techniqueConfig := src.Get("kubernetes.techniques." + techniqueID); techniqueConfig != nil {
		dst.Set("kubernetes", techniqueConfig)
	}
}

// GetTechniquePodConfig returns the merged pod configuration for a specific technique.
func (k *KubernetesConfigImpl) GetTechniquePodConfig(techniqueID string) K8sPodConfig {
	if k == nil || k.v == nil {
		return K8sPodConfig{}
	}
	merged := viper.New()
	k.populateViperOverride(k.v, merged, techniqueID)

	var podConfig K8sPodConfig
	if sub := merged.Sub("kubernetes.pod"); sub != nil {
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
	Tolerations []v1.Toleration   `yaml:"tolerations"`
	// mapstructure tags are used by Viper's Unmarshal; node_selector uses a tag because
	// the default (all-lowercase field name "nodeselector") differs from the YAML key.
	NodeSelector    map[string]string   `yaml:"node_selector" mapstructure:"node_selector"`
	SecurityContext *v1.SecurityContext `yaml:"securityContext"`
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
