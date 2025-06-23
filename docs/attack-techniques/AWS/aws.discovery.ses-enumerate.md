---
title: Enumerate SES
---

# Enumerate SES


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Discovery



## Description


Simulates an attacker enumerating SES. Attackers frequently use this enumeration technique after having compromised an access key, to use it to launch phishing campaigns or further resell stolen credentials.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Perform <code>ses:GetAccountSendingEnabled</code> to check if SES sending is enabled.
- Perform <code>ses:GetSendQuota</code> to discover the current [email sending quotas](https://docs.aws.amazon.com/ses/latest/APIReference/API_GetSendQuota.html).
- Perform <code>ses:ListIdentities</code> to discover the list of [identities](https://docs.aws.amazon.com/ses/latest/APIReference/API_ListIdentities.html) in the account.
- If identities are found, use <code>ses:GetIdentityVerificationAttributes</code> (only once) to discover [verification status](https://docs.aws.amazon.com/ses/latest/APIReference/API_GetIdentityVerificationAttributes.html) of each identity.

References:

- https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/#most-common-enumeration-techniques
- https://www.invictus-ir.com/news/ransomware-in-the-cloud
- https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/#post-125981-_kdq0vw6banab
- https://permiso.io/blog/s/aws-ses-pionage-detecting-ses-abuse/
- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.discovery.ses-enumerate
```
## Detection


Through CloudTrail's <code>GetAccountSendingEnabled</code>, <code>GetSendQuota</code> and <code>ListIdentities</code> events. 
These can be considered suspicious especially when performed by a long-lived access key, or when the calls span across multiple regions.


