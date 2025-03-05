---
title: Resetting or creating windows account 
---

# Resetting or creating windows account

<span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 

<span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Lateral Movement
- Persistence

## Description

Resetting existing windows account or create the account if it does not exist.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a compute instance (Windows)

<span style="font-variant: small-caps;">Detonation</span>:

- Create RSA key-pair (private key and public key)
- Request to reset windows account on compute instance
- Fetch and decrypt the password from compute instance.

Windows need few minutes to finish all setup after provisioning. So if the detonation fails, please wait for few minutes and try again.

Reference:

- https://cloud.google.com/sdk/gcloud/reference/compute/reset-windows-password



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.lateral-movement.reset-windows-account
```

## Detection


Resetting windows account is detected as 'compute.instances.setMetadata' in Cloud Logging

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
          "windows-keys public-key-here",
        ],
      },
    },
    "methodName": "v1.compute.instances.setMetadata",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
    "serviceName": "compute.googleapis.com",
  },
  "resource": {
    "type": "gce_instance"
  },
  "severity": "NOTICE"
}
```
