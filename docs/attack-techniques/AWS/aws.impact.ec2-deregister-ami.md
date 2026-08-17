---
title: Deregister an Amazon EC2 AMI
---

# Deregister an Amazon EC2 AMI




Platform: AWS

## Mappings

- MITRE ATT&CK
    - Impact


- Threat Technique Catalog for AWS:
  
    - [Data Destruction: AMI Image Deletion](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1485.A002.html) (T1485.A002)
  


## Description


Deregisters an EBS-backed AMI created by Stratus during warm-up.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an EBS volume
- Create a snapshot from the volume
- Register an EBS-backed AMI from the snapshot

<span style="font-variant: small-caps;">Detonation</span>:

- Call <code>DeregisterImage</code> on the AMI created during warm-up

References:

- https://aws.amazon.com/blogs/security/what-the-march-2026-threat-technique-catalog-update-means-for-your-aws-environment/
- https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1485.A002.html
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeregisterImage.html

Note: the AMI's backing EBS snapshot is not deleted during detonation.
Cleanup still removes the remaining snapshot and volume after the AMI has been deregistered outside Terraform.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.ec2-deregister-ami
```
## Detection


Through CloudTrail's <code>DeregisterImage</code> event, when an AMI owned by the compromised account is deregistered:

<pre><code>"eventSource": "ec2.amazonaws.com",
"eventName": "DeregisterImage",
"requestParameters": {
  "imageId": "ami-0b87ea1d007078d18",
  "deleteAssociatedSnapshots": false
}</code></pre>


