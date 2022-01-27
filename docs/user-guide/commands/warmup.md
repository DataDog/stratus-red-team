---
title: warmup
---
# `stratus warmup`

"Warm up" an attack technique by spinning up the prerequisite infrastructure or configuration, without detonating it.

For example, the attack technique [Exfiltrate an AMI by Sharing It](https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/) needs an AMI before the detonation phase can detonate the attack, and share it with an external AWS account.

## Sample Usage


```bash title="Warm up an attack technique"
stratus warmup aws.exfiltration.ec2-share-ami
```

```bash title="Warm up multiple attack techniques"
stratus warmup aws.exfiltration.ec2-share-ami aws.exfiltration.s3-backdoor-bucket-policy
```

```bash title="(advanced) Warm up again an attack technique that was already WARM, to ensure its prerequisites are met"
stratus warmup aws.exfiltration.ec2-share-ami --force
```