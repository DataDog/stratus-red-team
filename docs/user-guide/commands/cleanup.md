---
title: cleanup
---
# `stratus cleanup`

Cleans up any leftover infrastructure from an attack technique.

## Sample Usage

```bash title="Clean up an attack technique"
stratus cleanup aws.defense-evasion.cloudtrail-stop
```

```bash title="Clean up all attack techniques that can be cleaned up"
stratus cleanup --all
```

## Difference with `status revert`

`stratus revert` is about reverting the side effects of a detonation. In addition to reverting an attack technique, `stratus cleanup` also takes care of removing all prerequisite infrastructure from your live environment.