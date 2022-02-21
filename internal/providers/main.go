package providers

import (
	"errors"
	"github.com/datadog/stratus-red-team/pkg/stratus"
)

const StratusUserAgent = "stratus-red-team"

// EnsureAuthenticated ensures that the current user is properly authenticated against a specific platform
func EnsureAuthenticated(platform stratus.Platform) error {
	switch platform {
	case stratus.AWS:
		if !AWS().IsAuthenticatedAgainstAWS() {
			return errors.New("you are not authenticated against AWS, or you have not set your region. " +
				"Make sure you are authenticated against AWS, and you have a default region set in your AWS config " +
				"or environment (export AWS_DEFAULT_REGION=us-east-1)")
		}
	case stratus.Kubernetes:
		if !K8s().IsAuthenticated() {
			return errors.New("You do not have a kubeconfig set up, or you do not have proper permissions for " +
				"this cluster. Make sure you have proper credentials set in " + GetKubeConfigPath())
		}
	default:
		return errors.New("unhandled platform " + string(platform))
	}

	return nil
}
