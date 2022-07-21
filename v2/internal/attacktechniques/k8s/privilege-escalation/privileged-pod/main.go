package kubernetes

import (
	"context"
	"errors"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	v1 "k8s.io/api/core/v1"
	"log"

	_ "embed"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:embed main.tf
var tf []byte

const codeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.privilege-escalation.privileged-pod",
		FriendlyName:       "Run a Privileged Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		Description: `
Runs a privileged pod. Privileged pods are equivalent to running as root on the worker node, and can be used for privilege escalation.

Resources:

- https://www.cncf.io/blog/2020/10/16/hack-my-mis-configured-kubernetes-privileged-pods/
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

Warm-up: 

- Creates the Stratus Red Team namespace

Detonation: 

- Create a privileged busybox pod
`,
		Detection: `
Using Kubernetes API server audit logs, looking for pod creation events with <code>requestObject.spec.containers[*].securityContext.privileged</code>
set to <code>true</code>.

Sample event (shortened):

` + codeBlock + `json hl_lines="11 19 26"
{
	"objectRef": {
		"resource": "pods",
		"name": "k8s.privilege-escalation.privileged-pod",
		"apiVersion": "v1"
	},
	"http": {
		"url_details": {
			"path": "/api/v1/namespaces/stratus-red-team-umusjhhg/pods"
		},
		"method": "create",
		"status_code": 201
	},
	"stage": "ResponseComplete",
	"kind": "Event",
	"level": "RequestResponse",
	"requestURI": "/api/v1/namespaces/stratus-red-team-umusjhhg/pods",
	"requestObject": {
		"kind": "Pod",
		"spec": {
			"containers": [{
				"image": "busybox:stable",
				"args": ["while true; do sleep 3600; done"],
				"command": ["sh", "-c"],
				"securityContext": {
					"privileged": true
				}
			}]
		}
	}
}
` + codeBlock,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podSpec := podSpec(namespace)

	log.Println("Creating privileged pod " + podSpec.ObjectMeta.Name)
	_, err := client.CoreV1().Pods(namespace).Create(context.Background(), podSpec, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create pod: " + err.Error())
	}

	log.Println("Privileged pod " + podSpec.ObjectMeta.Name + " created in namespace " + namespace)
	return nil
}

func revert(params map[string]string) error {
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podSpec := podSpec(namespace)

	log.Println("Removing privileged pod " + podSpec.ObjectMeta.Name)
	deleteOptions := metav1.DeleteOptions{GracePeriodSeconds: ptr.Int64(0)}
	err := client.CoreV1().Pods(namespace).Delete(context.Background(), podSpec.ObjectMeta.Name, deleteOptions)
	if err != nil {
		return errors.New("unable to remove pod: " + err.Error())
	}

	return nil
}

func podSpec(namespace string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "k8s.privilege-escalation.privileged-pod",
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name:            "busybox",
				Image:           "busybox:stable",
				Command:         []string{"sh", "-c"},
				Args:            []string{"while true; do sleep 3600; done"},
				SecurityContext: &v1.SecurityContext{Privileged: ptr.Bool(true)},
			}},
		},
	}
}
