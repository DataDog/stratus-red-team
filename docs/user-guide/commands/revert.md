---
title: revert
---
# `stratus revert`

Reverts the detonation of an attack technique, when applicable.

Some attack techniques are not *idempotent*, meaning that you cannot detonate them multiple times because of their side-effect.
For instance, [Stop a CloudTrail Trail](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.stop-cloudtrail/) stops a CloudTrail Trail when detonated. Consequently, it cannot be detonated again (as the Trail is already stopped).

`stratus revert` ensures that a non-idempotent technique is reverted to a state where it can be detonated again.

## Sample Usage

```bash title="Revert an attack technique"
stratus revert aws.persistence.backdoor-lambda-function
```

## Difference with `stratus cleanup`

`stratus cleanup` both reverts an attack technique, *and* removes any deployed prerequisite infrastructure from your live environment. 
