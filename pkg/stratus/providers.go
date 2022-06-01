package stratus

import (
	"errors"
	"github.com/datadog/stratus-red-team/internal/providers"
)

func AWSProvider() *providers.AWSProvider {
	return providers.AWS()
}

func K8sProvider() *providers.K8sProvider {
	return providers.K8s()
}

// EnsureAuthenticated ensures that the current user is properly authenticated against a specific platform
func EnsureAuthenticated(platform Platform) error {
	switch platform {
	case AWS:
		if !providers.AWS().IsAuthenticatedAgainstAWS() {
			return errors.New("you are not authenticated against AWS, or you have not set your region. " +
				"Make sure you are authenticated against AWS, and you have a default region set in your AWS config " +
				"or environment (export AWS_DEFAULT_REGION=us-east-1)")
		}
	case Azure:
		if !providers.Azure().IsAuthenticatedAgainstAzure() {
			return errors.New("you are not authenticated against Azure, or you have not set your subscription. " +
				"Make sure you are authenticated against Azure and you have your Azure subscription ID set in your environment" +
				" (export AZURE_SUBSCRIPTION_ID=xxx)")
		}
	case Kubernetes:
		if !providers.K8s().IsAuthenticated() {
			return errors.New("You do not have a kubeconfig set up, or you do not have proper permissions for " +
				"this cluster. Make sure you have proper credentials set in " + providers.GetKubeConfigPath())
		}
	default:
		return errors.New("unhandled platform " + string(platform))
	}

	return nil
}
