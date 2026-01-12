package azure

import (
	"context"
	_ "embed"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.exfiltration.storage-sas-export",
		FriendlyName: "Exfiltrate Azure Storage through SAS URL",
		Description: `
[TODO: Add technique description]

Warm-up:
- [TODO: Describe prerequisites setup]

Detonation:
- [TODO: Describe attack execution]

References:
- [TODO: Add relevant documentation links]
`,
		Detection: `
[TODO: Add detection guidance]
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	_ = ctx

	log.Println("Starting technique execution")

	// TODO: Implement attack logic

	log.Println("Technique execution completed")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	_ = ctx

	log.Println("Starting cleanup")

	// TODO: Implement cleanup logic

	log.Println("Cleanup completed")
	return nil
}
