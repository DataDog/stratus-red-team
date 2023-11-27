---
title: Retrieve a High Number of Secrets Manager secrets (Batch)
---

# Retrieve a High Number of Secrets Manager secrets (Batch)


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Retrieves a high number of Secrets Manager secrets by batch, through <code>secretsmanager:BatchGetSecretValue</code> (released Novemeber 2023). 
An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets.


<span style="font-variant: small-caps;">Warm-up</span>: 

- Create multiple secrets in Secrets Manager.

<span style="font-variant: small-caps;">Detonation</span>: 

- Dump all secrets by batch of 10, using <code>secretsmanager:BatchGetSecretValue</code>.

References:

- https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.secretsmanager-batch-retrieve-secrets
```
## Detection


Identify principals that attempt to retrieve secrets by batch, through CloudTrail's <code>BatchGetSecretValue</code> event. Sample event:

```json
{
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "BatchGetSecretValue",
  "requestParameters": {
    "filters": [
      {
        "key": "tag-key",
        "values": [
          "StratusRedTeam"
        ]
      }
    ]
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "012345678901"
}
```

Although <code>BatchGetSecretValue</code> requires a list of secret IDs or a filter, an attacker may use a catch-all filter to retrieve all secrets by batch:

```json hl_lines="6-11"
{
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "BatchGetSecretValue",
  "requestParameters": {
    "filters": [
      {
        "key": "tag-key",
        "values": [
          "!tagKeyThatWillNeverExist"
        ]
      }
    ]
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "012345678901"
}
```

The following may be use to tune the detection, or validate findings:

- Principals who do not usually call GetBatchSecretValue
- Attempts to call GetBatchSecretValue resulting in access denied errors
- Principals calling GetBatchSecretValue in several regions in a short period of time

