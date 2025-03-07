---
title: Launch unusual GCE instances
---

# Launch unusual GCE instances


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span>

Platform: GCP

## MITRE ATT&CK Tactics


- Execution

## Description


Attempts to launch several unusual Compute Engine instances (default: `f1-micro`).

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM role that doesn't have permissions to launch Compute instance (roles/compute.viewer). This ensures the attempts is not successful, and the attack technique is fast to detonate.
- Assign caller with role 'roles/iam.serviceAccountTokenCreator' so it can impersonate service account.

<span style="font-variant: small-caps;">Detonation</span>: 

- Attempts to launch several unusual Compute instances. The calls will fail as the IAM role doesn't have sufficient permissions.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.execution.gce-launch-unusual-instances
```


## Detection 

Attempt to launch compute instance is detected as `compute.instances.insert` in Cloud Logging.

Sample event (shortened for readability):

```json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.insert",
    "resourceName": "projects/my-project-id/zones/my-zone-id/instances/my-instance-id",
  },
  "resource": {
    "type": "gce_instance",
  },
  "severity": "ERROR",
}
```