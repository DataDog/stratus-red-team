package stratus

import (
	"errors"
	"github.com/google/uuid"

	"github.com/datadog/stratus-red-team/v2/internal/providers"
)

// CloudProviders provides a unified interface to access the various cloud providers SDKs
type CloudProviders interface {
	AWS() *providers.AWSProvider
	K8s() *providers.K8sProvider
	Azure() *providers.AzureProvider
	GCP() *providers.GCPProvider
}

type CloudProvidersImpl struct {
	UniqueCorrelationID uuid.UUID
	AWSProvider         *providers.AWSProvider
	K8sProvider         *providers.K8sProvider
	AzureProvider       *providers.AzureProvider
	GCPProvider         *providers.GCPProvider
}

func (m CloudProvidersImpl) AWS() *providers.AWSProvider {
	if m.AWSProvider == nil {
		m.AWSProvider = providers.NewAWSProvider(m.UniqueCorrelationID)
	}
	return m.AWSProvider
}

func (m CloudProvidersImpl) K8s() *providers.K8sProvider {
	if m.K8sProvider == nil {
		m.K8sProvider = providers.NewK8sProvider(m.UniqueCorrelationID)
	}
	return m.K8sProvider
}

func (m CloudProvidersImpl) Azure() *providers.AzureProvider {
	if m.AzureProvider == nil {
		m.AzureProvider = providers.NewAzureProvider(m.UniqueCorrelationID)
	}
	return m.AzureProvider
}

func (m CloudProvidersImpl) GCP() *providers.GCPProvider {
	if m.GCPProvider == nil {
		m.GCPProvider = providers.NewGCPProvider(m.UniqueCorrelationID)
	}
	return m.GCPProvider
}

// EnsureAuthenticated ensures that the current user is properly authenticated against a specific platform
func EnsureAuthenticated(platform Platform) error {
	providerFactory := CloudProvidersImpl{UniqueCorrelationID: uuid.New()}
	switch platform {
	case AWS:
		if !providerFactory.AWS().IsAuthenticatedAgainstAWS() {
			return errors.New("you are not authenticated against AWS, or you have not set your region. " +
				"Make sure you are authenticated against AWS, and you have a default region set in your AWS config " +
				"or environment (export AWS_DEFAULT_REGION=us-east-1)")
		}
	case Azure:
		if !providerFactory.Azure().IsAuthenticatedAgainstAzure() {
			return errors.New("you are not authenticated against Azure, or you have not set your subscription. " +
				"Make sure you are authenticated against Azure and you have your Azure subscription ID set in your environment" +
				" (export AZURE_SUBSCRIPTION_ID=xxx)")
		}
	case Kubernetes:
		if !providerFactory.K8s().IsAuthenticated() {
			return errors.New("You do not have a kubeconfig set up, or you do not have proper permissions for " +
				"this cluster. Make sure you have proper credentials set in " + providers.GetKubeConfigPath())
		}
	case GCP:
		if !providerFactory.GCP().IsAuthenticated() {
			return errors.New("you are not authenticated against GCP, or you have not set your project. " +
				"Make sure you are authenticated against GCP and you have set your GCP Project ID in your environment variables" +
				" (export GOOGLE_PROJECT=xxx)")
		}
	default:
		return errors.New("unhandled platform " + string(platform))
	}

	return nil
}
