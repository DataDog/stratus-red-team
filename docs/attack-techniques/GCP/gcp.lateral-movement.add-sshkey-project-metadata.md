---
title: Register SSH Public Key to Project Metadata
---

# Register SSH Public Key to Project Metadata

<span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
<span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Lateral Movement
- Persistence

## Description

Register a public key to the project's metadata to allow login and gain access to any instance in the project.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a compute instance (Linux)

<span style="font-variant: small-caps;">Detonation</span>:

- Create RSA key-pair (private key and public key)
- Register public key to project's metadata.
- Print private key to stdout. 

Note that you need to save the private key for login. This key can be used to any instance belong to the same project.

Reference:
- https://cloud.google.com/sdk/gcloud/reference/compute/project-info/add-metadata
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/gcp-add-custom-ssh-metadata.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.lateral-movement.add-sshkey-project-metadata
```

## Detection


Registering SSH public key to the project's metadata is detected as 'compute.projects.setCommonInstanceMetadata' in Cloud Logging

Sample event (shortened for readability):

```json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
	"serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.projects.setCommonInstanceMetadata",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
  },
  "resource": {
    "type": "gce_project"
  },
  "severity": "NOTICE"
}
```
