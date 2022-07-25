package domain

import "github.com/datadog/stratus-red-team/v2/internal/providers"

type ProvidersFactory interface {
	GetAWSProvider() *providers.AWSProvider
	GetK8sProvider() *providers.K8sProvider
	GetAzureProvider() *providers.AzureProvider
}
