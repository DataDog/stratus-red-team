package kubernetes

import (
	"archive/tar"
	"bytes"
	"context"
	"io/fs"
	"log"
	"net/url"
	"path"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// createExecutor returns an executor with WebSocket, falling back to SPDY
//
// Code from kubectl/pkg/cmd/exec/exec.go
func createExecutor(config *rest.Config, reqURL *url.URL) (remotecommand.Executor, error) {
	spdyExec, err := remotecommand.NewSPDYExecutor(config, "POST", reqURL)
	if err != nil {
		return nil, err
	}

	websocketExec, err := remotecommand.NewWebSocketExecutor(config, "GET", reqURL.String())
	if err != nil {
		return nil, err
	}

	return remotecommand.NewFallbackExecutor(websocketExec, spdyExec, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
}

// CopyBytesToPod copies input bytes to a file in a pod. destPath can be an absolute path
// (e.g., "/tmp/file.js") or just a filename(e.g., "file.js"), in which case it will be placed in
// the container's working directory.
func CopyBytesToPod(
	ctx context.Context,
	config *rest.Config,
	client *kubernetes.Clientset,
	namespace, podName, containerName string,
	content []byte,
	destPath string,
) error {
	destDir, destFile := path.Split(destPath)

	// Match kubectl behavior: empty dir means current working directory
	if destDir == "" {
		destDir = "."
	}

	tarBuffer, err := createTarForFile(content, destFile)
	if err != nil {
		return err
	}

	// Use sh -c to create the directory if it doesn't exist before extracting
	cmdArr := []string{"sh", "-c", "mkdir -p " + destDir + " && tar -xmf - -C " + destDir}

	execOptions := &v1.PodExecOptions{
		Container: containerName,
		Command:   cmdArr,
		Stdin:     true,
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
		return err
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  tarBuffer,
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
		Tty:    false, // Explicitly disable TTY
	})
	if err != nil {
		log.Println("Error streaming context: " + err.Error() + " - stdout: " + stdoutBuf.String() + " - stderr: " + stderrBuf.String())
		return err
	}
	return nil
}

// CopyFilesToPod copies a map of bytes, representing multiple embedded files to a directory in a pod.
// files is a map of filename -> content, where filenames are relative paths within destDir.
// destDir should be an absolute path (e.g., "/tmp/app") or "." for the container's working directory.
func CopyFilesToPod(
	ctx context.Context,
	config *rest.Config,
	client *kubernetes.Clientset,
	namespace, podName, containerName string,
	files map[string][]byte,
	destDir string,
) error {
	if destDir == "" {
		destDir = "."
	}

	tarBuffer, err := createTarForFiles(files)
	if err != nil {
		return err
	}

	// Use sh -c to create the directory if it doesn't exist before extracting
	cmdArr := []string{"sh", "-c", "mkdir -p " + destDir + " && tar -xmf - -C " + destDir}

	execOptions := &v1.PodExecOptions{
		Container: containerName,
		Command:   cmdArr,
		Stdin:     true,
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
		return err
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  tarBuffer,
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
		Tty:    false,
	})
	if err != nil {
		log.Println("Error streaming context: " + err.Error() + " - stdout: " + stdoutBuf.String() + " - stderr: " + stderrBuf.String())
		return err
	}
	return nil
}

// createTarForFile creates a tar archive containing a single file
func createTarForFile(content []byte, filename string) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	header := &tar.Header{
		Name:    filename,
		Mode:    0644,
		Size:    int64(len(content)),
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return nil, err
	}

	if _, err := tw.Write(content); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	return bytes.NewReader(buf.Bytes()), nil
}

// createTarForFiles creates a tar archive containing multiple files
func createTarForFiles(files map[string][]byte) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for filename, content := range files {
		header := &tar.Header{
			Name:    filename,
			Mode:    0644,
			Size:    int64(len(content)),
			ModTime: time.Now(),
		}

		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}

		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	return bytes.NewReader(buf.Bytes()), nil
}

// CopyFSToPod copies all files from an fs.FS (e.g., embed.FS) to a directory in a pod.
// destDir should be an absolute path (e.g., "/tmp/app") or "." for the container's working directory.
func CopyFSToPod(
	ctx context.Context,
	config *rest.Config,
	client *kubernetes.Clientset,
	namespace, podName, containerName string,
	srcFS fs.FS,
	destDir string,
) error {
	files, err := ReadFSToMap(srcFS)
	if err != nil {
		return err
	}
	return CopyFilesToPod(ctx, config, client, namespace, podName, containerName, files, destDir)
}

// ReadFSToMap reads all files from an fs.FS into a map of filename -> content.
// This is useful for converting embed.FS to a format suitable for CopyFilesToPod.
func ReadFSToMap(srcFS fs.FS) (map[string][]byte, error) {
	files := make(map[string][]byte)

	err := fs.WalkDir(srcFS, ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		content, err := fs.ReadFile(srcFS, filePath)
		if err != nil {
			return err
		}

		files[filePath] = content
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
