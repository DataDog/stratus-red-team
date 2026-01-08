package kubernetes

import (
	"bytes"
	"context"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecInPod executes a command in a pod and returns stdout and stderr.
func ExecInPod(
	ctx context.Context,
	config *rest.Config,
	client *kubernetes.Clientset,
	namespace, podName, containerName string,
	command []string,
) (stdout string, stderr string, err error) {
	execOptions := &v1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
	}

	req := client.CoreV1().RESTClient().Post().
		Namespace(namespace).
		Resource("pods").
		Name(podName).
		SubResource("exec")
	req.VersionedParams(execOptions, scheme.ParameterCodec)

	executor, err := createExecutor(config, req.URL())
	if err != nil {
		return "", "", err
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
		Tty:    false, // Explicitly disable TTY
	})

	return stdoutBuf.String(), stderrBuf.String(), err
}
