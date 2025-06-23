---
title: Open Ingress Port 22 on a Security Group
---

# Open Ingress Port 22 on a Security Group




Platform: AWS

## Mappings

- MITRE ATT&CK
    - Exfiltration


- Threat Technique Catalog for AWS:
  
    - [Impair Defenses: Disable or Modify Cloud Firewall](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1562.007.html) (T1562.007)
  


## Description


Opens ingress traffic on port 22 from the Internet (0.0.0.0/0).

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a VPC and a security group inside it.

<span style="font-variant: small-caps;">Detonation</span>: 

- Call ec2:AuthorizeSecurityGroupIngress to allow ingress traffic on port 22 from 0.0.0.0/0.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ec2-security-group-open-port-22-ingress
```
## Detection


You can use the CloudTrail event <code>AuthorizeSecurityGroupIngress</code> when:

- <code>requestParameters.cidrIp</code> is <code>0.0.0.0/0</code> (or an unknown external IP)
- and <code>requestParameters.fromPort</code>/<code>requestParameters.toPort</code> is not a commonly exposed port or corresponds to a known administrative protocol such as SSH or RDP



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ec2:AuthorizeSecurityGroupIngress`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "us-northeast-1r",
	      "eventCategory": "Management",
	      "eventID": "9fd68588-ecbf-4528-a345-199fa6bb0821",
	      "eventName": "AuthorizeSecurityGroupIngress",
	      "eventSource": "ec2.amazonaws.com",
	      "eventTime": "2024-08-01T12:23:55Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "032092706103",
	      "requestID": "dc1dabbf-d7cb-4966-a3de-ac69d5cfc633",
	      "requestParameters": {
	         "cidrIp": "208.236.235.254/0",
	         "fromPort": 22,
	         "groupId": "sg-003dc7f1f1c686164",
	         "ipPermissions": {},
	         "ipProtocol": "tcp",
	         "toPort": 22
	      },
	      "responseElements": {
	         "_return": true,
	         "requestId": "dc1dabbf-d7cb-4966-a3de-ac69d5cfc633",
	         "securityGroupRuleSet": {
	            "items": [
	               {
	                  "cidrIpv4": "208.236.235.254/0",
	                  "fromPort": 22,
	                  "groupId": "sg-003dc7f1f1c686164",
	                  "groupOwnerId": "032092706103",
	                  "ipProtocol": "tcp",
	                  "isEgress": false,
	                  "securityGroupRuleId": "sgr-09b3e3d2ca1edf2a2",
	                  "toPort": 22
	               }
	            ]
	         }
	      },
	      "sourceIPAddress": "253.243.215.253",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2.us-northeast-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_1004a4ff-b486-4981-a84b-6322905f37cc",
	      "userIdentity": {
	         "accessKeyId": "AKIAXW7UJ577KFYIAHIM",
	         "accountId": "032092706103",
	         "arn": "arn:aws:iam::032092706103:user/christophe",
	         "principalId": "AIDAQ5Y2TGCDATQV6SRP",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
