---
title: detonate
---
# `stratus detonate`

Detonates an attack technique.

* If the technique was previously warmed up using `stratus warmup`, it will not be warmed up again.
* Otherwise, `stratus detonate` will automatically warm up the technique before detonating it.

## Sample Usage

```bash title="Detonate an attack technique"
stratus detonate aws.exfiltration.backdoor-s3-bucket-policy
```

```bash title="Detonate multiple attack techniques"
stratus detonate aws.exfiltration.backdoor-s3-bucket-policy aws.defense-evasion.stop-cloudtrail
```

```bash title="Detonate an attack technique, then automatically clean up any resources deployed on AWS"
stratus detonate aws.exfiltration.backdoor-s3-bucket-policy --cleanup
```