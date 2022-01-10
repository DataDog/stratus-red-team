package stratus

import "errors"

type Platform string

const (
	AWS = "aws"
)

func PlatformFromString(name string) (Platform, error) {
	switch name {
	case AWS:
		return AWS, nil
	default:
		return "", errors.New("unknown platform: " + name)
	}
}
