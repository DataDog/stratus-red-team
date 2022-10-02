package stratus

import (
	"errors"
	"strings"
)

type Platform string

const (
	AWS        = "AWS"
	Kubernetes = "kubernetes"
	Azure      = "azure"
	GCP        = "GCP"
)

func PlatformFromString(name string) (Platform, error) {
	switch strings.ToLower(name) {
	case strings.ToLower(AWS):
		return AWS, nil
	case strings.ToLower(Kubernetes):
		return Kubernetes, nil
	case strings.ToLower(Azure):
		return Azure, nil
	case strings.ToLower(GCP):
		return GCP, nil
	default:
		return "", errors.New("unknown platform: " + name)
	}
}

func (p Platform) FormatName() (string, error) {
	switch p {
	case AWS:
		return "AWS", nil
	case Azure:
		return "Azure", nil
	case GCP:
		return "GCP", nil
	case Kubernetes:
		return "Kubernetes", nil
	default:
		return "", errors.New("platform name not formatted")
	}
}

// MarshalYAML implements the Marshaler interface from "gopkg.in/yaml.v3".
// It uses the formatted name when marshalling to YAML. "Azure" instead of "azure", etc.
func (p Platform) MarshalYAML() (interface{}, error) {
	return p.FormatName()
}
