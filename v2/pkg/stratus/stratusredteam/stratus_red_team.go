package stratusredteam

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/domain"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"github.com/google/uuid"
	"path/filepath"
)

type ProvidersFactoryImpl struct {
	AWSProvider   *providers.AWSProvider
	K8sProvider   *providers.K8sProvider
	AzureProvider *providers.AzureProvider
}

func (m ProvidersFactoryImpl) GetAWSProvider() *providers.AWSProvider {
	return m.AWSProvider
}

func (m ProvidersFactoryImpl) GetK8sProvider() *providers.K8sProvider {
	return m.K8sProvider
}

func (m ProvidersFactoryImpl) GetAzureProvider() *providers.AzureProvider {
	return m.AzureProvider
}

type StratusRedTeam struct {
	Providers      domain.ProvidersFactory
	DetonationUuid uuid.UUID
}

type StratusRedTeamOptions struct {
	AwsConfig      *aws.Config
	DetonationUuid uuid.UUID
}

func NewStratusRedTeam(optsFunc ...func(options *StratusRedTeamOptions)) *StratusRedTeam {
	options := StratusRedTeamOptions{DetonationUuid: uuid.New()}
	for i := range optsFunc {
		optsFunc[i](&options)
	}
	providersFactory := ProvidersFactoryImpl{}
	providersFactory.AWSProvider = &providers.AWSProvider{UniqueCorrelationId: options.DetonationUuid, AwsConfig: options.AwsConfig}
	providersFactory.K8sProvider = &providers.K8sProvider{UniqueCorrelationId: options.DetonationUuid}
	providersFactory.AzureProvider = &providers.AzureProvider{UniqueCorrelationId: options.DetonationUuid}

	return &StratusRedTeam{
		Providers:      providersFactory,
		DetonationUuid: options.DetonationUuid,
	}
}

func (m *StratusRedTeam) NewRunner(technique *domain.AttackTechnique, force bool) stratusrunner.Runner {
	stateManager := state.NewFileSystemStateManager(technique)
	terraformBinary := filepath.Join(stateManager.GetRootDirectory(), "terraform")
	userAgent := providers.GetStratusUserAgent(m.DetonationUuid.String())
	runner := stratusrunner.Runner{
		Technique:         technique,
		ShouldForce:       force,
		TerraformManager:  stratusrunner.NewTerraformManager(terraformBinary, userAgent),
		StateManager:      stateManager,
		Providers:         m.Providers,
		UniqueExecutionId: m.DetonationUuid,
	}
	runner.Initialize()

	return runner
}
