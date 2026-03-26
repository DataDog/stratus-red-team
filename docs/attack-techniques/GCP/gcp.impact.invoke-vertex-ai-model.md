---
title: Invoke a Vertex AI Model
---

# Invoke a Vertex AI Model


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Invokes a Gemini generative AI model via the Vertex AI API. This simulates
an attacker who has obtained access to a GCP service account and abuses it
to run large language model workloads, incurring unexpected costs for the
victim organization.

Prerequisites:

- AI Platform API enabled (gcloud services enable aiplatform.googleapis.com)

<span style="font-variant: small-caps;">Detonation</span>:

- Call the Vertex AI API to generate content using a Gemini model
  in the <code>us-central1</code> region

References:

- https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference
- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.endpoints/generateContent


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.invoke-vertex-ai-model
```
## Detection


Identify unexpected Vertex AI model invocations by monitoring for
<code>google.cloud.aiplatform.v1.PredictionService.GenerateContent</code> events in
GCP Data Access audit logs, particularly from unexpected service accounts or at
unusual times/volumes.


