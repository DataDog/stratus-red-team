---
title: Register SSH public key to instance metadata
---

# Register SSH public key to instance metadata


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Lateral Movement
  - Persistence



## Description


Register a public key to the instance's metadata to allow login and gain access to the instance.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a compute instance (Linux)

<span style="font-variant: small-caps;">Detonation</span>:

- Create RSA key-pair (private key and public key)
- Register public key to instance's metadata.
- Print private key to stdout. 

Note that you need to save the private key for login.

Reference:
- https://cloud.google.com/sdk/gcloud/reference/compute/instances/add-metadata
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/gcp-add-custom-ssh-metadata.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.lateral-movement.add-sshkey-instance-metadata
```
## Detection


Registering SSH public key to the instance's metadata is detected as 'compute.instances.setMetadata' in Cloud Logging

Sample event (shortened for readability):

```json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "metadata": {
      "instanceMetadataDelta": {
        "addedMetadataKeys": [
          "ssh-keys public-key-here",
        ],
      },
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.setMetadata",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
  },
  "resource": {
    "type": "gce_instance"
  },
  "severity": "NOTICE"
}
```


