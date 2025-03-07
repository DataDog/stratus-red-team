package gcp

import (
    "context"
    _ "embed"
    "errors"
    "strings"
    "fmt"
    "log"
    "google.golang.org/api/compute/v1"
    "google.golang.org/api/impersonate"
    "google.golang.org/api/option"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const instanceType = "f1-micro"
const imageSource  = "projects/debian-cloud/global/images/family/debian-12"
const numInstances = 10


func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.execution.gce-launch-unusual-instances"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "Launch unusual GCE instances",
        Description: `
Attempts to launch several unusual Compute Engine instances (` + string(instanceType) + `).

Warm-up: 

- Create an IAM role that doesn't have permissions to launch Compute instance (roles/compute.viewer). This ensures the attempts is not successful, and the attack technique is fast to detonate.
- Assign caller with role 'roles/iam.serviceAccountTokenCreator' so it can impersonate service account.

Detonation:

- Attempts to launch several unusual Compute instances. The calls will fail as the IAM role doesn't have sufficient permissions.
`,
        Detection: `
Attempt to launch compute instance is detected as 'compute.instances.insert' in Cloud Logging.

` + CodeBlock + `json
{
  logName: "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  protoPayload: {
    authenticationInfo: {
      principalEmail: "username@service.com"
    }
    methodName: "v1.compute.instances.insert"
    resourceName: "projects/my-project-id/zones/my-zone-id/instances/my-instance-id"
  }
  resource: {
    type: "gce_instance"
  }
  severity: "ERROR"
}
` + CodeBlock + `
`,
        Platform:                   stratus.GCP,
        IsIdempotent:               true,
        MitreAttackTactics:         []mitreattack.Tactic{ mitreattack.Execution },
        PrerequisitesTerraformCode: tf,
        Detonate:                   detonate,
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    log.Printf("Attempting to run up to %d instances of type ", numInstances)

    hostName    := "stratusvm"
    diskName    := "stratusvm-disk"

    saEmail     := params["sa_email"]
    zone        := params["zone"]
    network     := params["network"]
    subnet      := params["subnet"]

    diskType    := fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-ssd", gcp.GetProjectId(), zone)
    machineType := fmt.Sprintf("projects/%s/zones/%s/machineTypes/%s", gcp.GetProjectId(), zone, instanceType)
    
    log.Printf("Impersonating '%s' service account", saEmail)

    // create the token for service account
    token, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig {
        TargetPrincipal: saEmail,
        Scopes: []string{
            compute.CloudPlatformScope,
            compute.ComputeScope,
        },
    })

    service, err := compute.NewService(ctx, option.WithTokenSource(token))
    if err != nil {
        return fmt.Errorf("Failed to create compute service: %v", err)
    }

    log.Printf("Launching instance: zone='%s'", zone)

    for idx := 0; idx < numInstances; idx++ {
        // request for instance creation
        req := &compute.Instance {
            Name:           hostName,
            Description:    "gcp.execution.gce-launch-unusual-instances SCENARIO",
            MachineType:    machineType,
            Disks:          []*compute.AttachedDisk {
                {
                    AutoDelete: true,
                    Boot:       true,
                    Type:       "PERSISTENT",
                    InitializeParams: &compute.AttachedDiskInitializeParams {
                        DiskName:    diskName,
                        DiskType:    diskType,
                        SourceImage: imageSource,
                    },
                },
            },
            NetworkInterfaces: []*compute.NetworkInterface {
                {
                    Network:    network,
                    Subnetwork: subnet,
                },
            },
        }

        // attempt to create instance (should be failed) and err has value
        if _, err := service.Instances.Insert(gcp.GetProjectId(), zone, req).Do(); err == nil {
            return errors.New("expected to return an error")
        // it should be forbidden because we don't have permission to create instance
        } else if !strings.Contains(err.Error(), "forbidden") {
            return errors.New("expected to return forbidden due to lack of permissions")
        }

        log.Printf("Launch-%d: Got a permission denied as expected\n", idx)
    }

    return nil
}