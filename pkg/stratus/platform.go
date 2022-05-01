package stratus

import (
	"errors"
	"strings"
)

type Platform string

const (
	AWS        = "AWS"
	Kubernetes = "kubernetes"
	Azure      = "Azure"
)

func PlatformFromString(name string) (Platform, error) {
	switch strings.ToLower(name) {
	case strings.ToLower(AWS):
		return AWS, nil
	case strings.ToLower(Kubernetes):
		return Kubernetes, nil
	case strings.ToLower(Azure):
		return Azure, nil
	default:
		return "", errors.New("unknown platform: " + name)
	}
}
