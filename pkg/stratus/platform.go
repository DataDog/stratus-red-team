package stratus

import (
	"errors"
	"strings"
)

type Platform string

const (
	AWS        = "AWS"
	Kubernetes = "Kubernetes"
)

func PlatformFromString(name string) (Platform, error) {
	switch strings.ToLower(name) {
	case strings.ToLower(AWS):
		return AWS, nil
	case strings.ToLower(Kubernetes):
		return Kubernetes, nil
	default:
		return "", errors.New("unknown platform: " + name)
	}
}
