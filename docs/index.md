# Home

Welcome to the documentation of Stratus Red Team!

Check out:

- The [User Guide](./user-guide), to get started
- The list of [available techniques](./attack-techniques)

## About Stratus Red Team

Think of Stratus Red Team as "[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)™" for the cloud.

When crafting and implementing threat detection rules, it is essential to have an easy way to execute granular attack techniques, to be able to validate that our detections work as expected.

Stratus Red Team is a self-contained binary. You can use it to easily detonate offensive attack techniques against a live cloud environment.

```bash title="Sample usage - Stopping a CloudTrail Trail (Defense Evasion)"
stratus detonate aws.defense-evasion.stop-cloudtrail
```

The attack techniques are mapped to [MITRE ATT&CK](https://attack.mitre.org/).
