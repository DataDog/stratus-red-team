---
title: Delete DNS query logs
---

# Delete DNS query logs




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Deletes a Route53 DNS Resolver query logging configuration. Simulates an attacker disrupting DNS logging.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a DNS logging configuration.

<span style="font-variant: small-caps;">Detonation</span>:

- Delete the DNS logging configuration using <code>route53:DeleteQueryLoggingConfig</code>.

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.dns-delete-logs
```
## Detection


Identify when a DNS logging configuration is deleted, through CloudTrail's <code>DeleteResolverQueryLogConfig</code> event.


