package stratus

import (
	"errors"
	"strings"
)

type Platform string

const (
	AWS = "AWS"
)

func PlatformFromString(name string) (Platform, error) {
	switch strings.ToLower(name) {
	case strings.ToLower(AWS):
		return AWS, nil
	default:
		return "", errors.New("unknown platform: " + name)
	}
}
