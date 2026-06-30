---
title: show
---
# `stratus show`

## Sample Usage

```bash title="Display more information about an attack technique"
stratus show aws.credential-access.ec2-steal-instance-credentials
```

```bash title="Output the full technique details as JSON"
stratus show aws.credential-access.ec2-steal-instance-credentials --output json
```

In JSON mode, `show` outputs the technique's full metadata — including its
`description`, `detection` guidance, `mitreAttackTactics` and any framework
mappings — as a JSON array.