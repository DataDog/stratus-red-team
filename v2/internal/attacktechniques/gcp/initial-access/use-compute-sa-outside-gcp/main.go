package gcp

import (
	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"log"
	"strings"
	"time"
)

//go:embed main.tf
var tf []byte

const (
	tokenStartMarker = "STRATUS_TOKEN_START"
	tokenEndMarker   = "STRATUS_TOKEN_END"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.initial-access.use-compute-sa-outside-gcp",
		FriendlyName: "Steal and Use the GCE Default Service Account Token from Outside Google Cloud",
		IsSlow:       true,
		Description: `
Simulates the theft and use of GCE default service account credentials from outside of Google Cloud.

When a GCE instance is created, it is assigned a default service account
(<code>{project-number}-compute@developer.gserviceaccount.com</code>).
If an attacker gains access to the instance (for example through an SSRF vulnerability,
a compromised SSH key, or a command injection), they can extract the OAuth2 access token
from the <a href="https://cloud.google.com/compute/docs/metadata/overview">instance metadata service</a>
and use it from outside of Google Cloud.

Warm-up:

- Create a GCE instance running with the default compute service account
- The instance runs a startup script that extracts the service account OAuth2 token from the instance metadata service and writes it to the serial port

Detonation:

- Read the instance's serial port output to extract the stolen OAuth2 token
- Use the stolen token from outside Google Cloud to set labels on the GCE instance, generating a GCP Admin Activity audit log from a non-Google IP address

References:

- https://about.gitlab.com/blog/plundering-gcp-escalating-privileges-in-google-cloud-platform/
- https://securitylabs.datadoghq.com/articles/google-cloud-default-service-accounts/
- https://cloud.google.com/compute/docs/access/service-accounts#default_service_account
`,
		Detection: `
Identify when a GCE default service account (<code>*-compute@developer.gserviceaccount.com</code>) is used from outside of Google Cloud
by analyzing GCP audit logs.

The GCE default service account should typically only be used from within Google Cloud (e.g., from a GCE instance).
Usage from external IP addresses with non-GCE user agents indicates potentially stolen credentials.

Detection criteria:

<ul>
  <li>Monitor GCP audit logs where the caller identity matches <code>*-compute@developer.gserviceaccount.com</code></li>
  <li>Filter for calls where the caller IP does not belong to Google's IP ranges</li>
  <li>Exclude calls with user agents containing <code>GCE</code> or <code>gcloud</code> (which indicate legitimate in-cloud usage)</li>
</ul>
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess, mitreattack.InitialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// tokenResponse represents the JSON response from the GCE metadata token endpoint
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	saEmail := params["sa_email"]
	instanceName := params["instance_name"]
	zone := params["zone"]

	// Step 1: Read the stolen OAuth2 token from the instance's serial port output
	log.Println("Reading stolen OAuth2 token from instance serial port output")
	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	stolenTokenJSON, err := readTokenFromSerialPort(ctx, instancesClient, projectId, zone, instanceName)
	if err != nil {
		return fmt.Errorf("failed to read stolen token from serial port: %w", err)
	}

	var token tokenResponse
	if err := json.Unmarshal([]byte(stolenTokenJSON), &token); err != nil {
		return fmt.Errorf("failed to parse stolen OAuth2 token: %w", err)
	}

	log.Printf("Successfully extracted OAuth2 access token for %s from instance metadata\n", saEmail)

	// Step 2: Use the stolen token from outside Google Cloud
	stolenTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
	})
	stolenClient, err := compute.NewInstancesRESTClient(ctx, option.WithTokenSource(stolenTokenSource))
	if err != nil {
		return fmt.Errorf("failed to create compute client with stolen credentials: %w", err)
	}
	defer stolenClient.Close()

	// Get the instance to obtain the current label fingerprint
	log.Printf("Getting instance %s details using stolen credentials\n", instanceName)
	instance, err := stolenClient.Get(ctx, &computepb.GetInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("failed to get instance with stolen credentials: %w", err)
	}

	// Set labels on the instance using the stolen credentials
	// This generates an Admin Activity audit log from outside Google Cloud
	log.Printf("Setting labels on instance %s using stolen compute service account credentials\n", instanceName)
	_, err = stolenClient.SetLabels(ctx, &computepb.SetLabelsInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
		InstancesSetLabelsRequestResource: &computepb.InstancesSetLabelsRequest{
			Labels: map[string]string{
				"stratus-red-team": "true",
			},
			LabelFingerprint: instance.LabelFingerprint,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set labels on instance: %w", err)
	}

	log.Printf("Successfully used stolen GCE default service account %s from outside Google Cloud\n", saEmail)
	return nil
}

// readTokenFromSerialPort polls the instance serial port output for the stolen token
func readTokenFromSerialPort(ctx context.Context, client *compute.InstancesClient, projectId, zone, instanceName string) (string, error) {
	port := int32(1)
	for i := 0; i < 40; i++ {
		output, err := client.GetSerialPortOutput(ctx, &computepb.GetSerialPortOutputInstanceRequest{
			Project:  projectId,
			Zone:     zone,
			Instance: instanceName,
			Port:     &port,
		})
		if err == nil && output.Contents != nil {
			tokenJSON := extractToken(*output.Contents)
			if tokenJSON != "" {
				return tokenJSON, nil
			}
		}
		if i == 0 {
			log.Println("Waiting for instance startup script to write OAuth2 token to serial port...")
		}
		time.Sleep(5 * time.Second)
	}

	return "", fmt.Errorf("timed out waiting for OAuth2 token in serial port output (instance startup script may have failed)")
}

// extractToken finds the last occurrence of the token between markers in serial port output
func extractToken(serialOutput string) string {
	lastStart := strings.LastIndex(serialOutput, tokenStartMarker)
	if lastStart == -1 {
		return ""
	}
	remainder := serialOutput[lastStart+len(tokenStartMarker):]
	endIdx := strings.Index(remainder, tokenEndMarker)
	if endIdx == -1 {
		return ""
	}
	return remainder[:endIdx]
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	ctx := context.Background()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	zone := params["zone"]

	// Use the user's own credentials for cleanup
	instancesClient, err := compute.NewInstancesRESTClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	// Get current label fingerprint
	instance, err := instancesClient.Get(ctx, &computepb.GetInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
	})
	if err != nil {
		return fmt.Errorf("failed to get instance: %w", err)
	}

	// Remove the labels we set during detonation
	log.Printf("Removing labels from instance %s\n", instanceName)
	_, err = instancesClient.SetLabels(ctx, &computepb.SetLabelsInstanceRequest{
		Project:  projectId,
		Zone:     zone,
		Instance: instanceName,
		InstancesSetLabelsRequestResource: &computepb.InstancesSetLabelsRequest{
			Labels:           map[string]string{},
			LabelFingerprint: instance.LabelFingerprint,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to remove labels from instance: %w", err)
	}

	log.Println("Successfully removed labels from instance")
	return nil
}
