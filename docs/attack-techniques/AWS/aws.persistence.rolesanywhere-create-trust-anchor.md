---
title: Create an IAM Roles Anywhere trust anchor
---

# Create an IAM Roles Anywhere trust anchor




Platform: AWS

## Mappings

- MITRE ATT&CK
    - Persistence
  - Privilege Escalation



## Description


Establishes persistence by creating an IAM Roles Anywhere trust anchor. 
The IAM Roles Anywhere service allows workloads that do not run in AWS to assume roles by presenting a client-side 
X.509 certificate signed by a trusted certificate authority, called a "trust anchor".

Assuming IAM Roles Anywhere is in use (i.e., that some of the IAM roles in the account have a 
[trust policy](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html#trust-policy) trusting 
the IAM Roles Anywhere service), an attacker creating a trust anchor can subsequently assume these roles.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM role that can be used by IAM Roles Anywhere (see [docs](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step2))

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM Roles Anywhere trust anchor
- Create an IAM Roles Anywhere profile

References:

- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.rolesanywhere-create-trust-anchor
```
## Detection


Identify when a trust anchor is created, through CloudTrail's <code>CreateTrustAnchor</code> event.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `rolesanywhere:CreateProfile`

- `rolesanywhere:CreateTrustAnchor`


??? "View raw detonation logs"

    ```json hl_lines="6 83"

    [
	   {
	      "awsRegion": "cn-northsouth-3r",
	      "eventCategory": "Management",
	      "eventID": "66e5f252-e092-4ad0-9a33-a03595e05aca",
	      "eventName": "CreateTrustAnchor",
	      "eventSource": "rolesanywhere.amazonaws.com",
	      "eventTime": "2024-08-01T13:56:39Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.10",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "791182566784",
	      "requestID": "4f8955b7-2a80-43c8-8f56-055883a07632",
	      "requestParameters": {
	         "enabled": true,
	         "name": "malicious-rolesanywhere-trust-anchor",
	         "source": {
	            "sourceData": {
	               "x509CertificateData": "-----BEGIN CERTIFICATE-----\nMIIE3zCCAsegAwIBAgIJAOZLUn/n7YvYMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNV\nBAYTAkVTMB4XDTIyMDcxMDIxMjgxOVoXDTMyMDcwNzIxMjgxOVowDTELMAkGA1UE\nBhMCRVMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDb0ga7LzegYNXV\noBTY7ByNCtgqAEoZVQAEQAxpWzK4wL4V+TKRRGiP9KQSbMsU35dBuxzg2Ih62dwr\nh6S7vYX4eU8YpGcutrWekzAl+G4GwfbHcwJYt9ALrneFUUWEedYA6BTVG0b+cwIL\nOkVJSlB/4bAVFocwafdnFi3CLsIhXF/Yn90mnug+qsXSWPMZmTXaykiO9+AWV/pO\n/JNS2WLPp4EKUT3CGm12TxBMHG0sWG0xopuj4KXTsyJFELDevSo92ldqyCIJFgG8\nwBmbETxx9TlTPEU6hVkG4MLE2ekkEQK8WVLpZvTGFRrauawMhAzfFV9ZcgIsURy7\nv2/FlYL7OedesimPfGD8M1dkm4yK2dVvUf/HyEL1IB1+3NtAOoifZ5jBBJKaybF0\n/W85asZWVg+yKokFhmQRzu4BFnPhsoTwau+WuySYokbWIEzdW8FljWpwiPlvnqy+\nVJVKdZuzWx12yLzK5srQ4Qcb/tQqkooVASM0PH5ts3PYlf5hRgxqKgCR5lXODxoA\n0aylk6+wC2oBLhvufmwObsOMcxMbPv+EQvzYChL1MRLvEPAmATiE64ZLn8IOu9MG\n9GRC6D/NkLy9LdsPWfzx+W1itrWR3ft/uD/HXILAVc54HejbZGsPsLe7qITDNc7n\nD5zM+orgu67zgRaBOm1kPZbr/vHUFQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYw\nHQYDVR0OBBYEFJNT8WprixUiturSY9GAHXmAcP/RMA8GA1UdEwEB/wQFMAMBAf8w\nDQYJKoZIhvcNAQELBQADggIBAJ1clg4GzHuMxTmpz+riL2klUZEMpJPvy682c0iH\nNlG0f30cNHdSlnhCnx78h3n1xotSM8zZf6+LepCZWCzho5p3Fep7sDumQ+chgdIp\nNApgcGX7tpx+TVjrrwkpxioMSfVFHJ7RMSewumnOXw4NsUQmGJdku8FUR7BWRRiY\nfk0MoQ9nuwjt+RcSz/IKdFTzjI70nPikjSSd0L/ovWk5aXgLcnZpgzv6r4HbafJU\n7dEnP+paZugEUts+SNXr3vkSuiLod7iiOcmQFvtRDFUAn4QonoN/6lDDOGLYsy0J\nrv9GI+Y5VYt6JRGNJq/yCBV1KhhjaWll0kl/UNxIr+hBQ5Vul9SiR3jbbNlRh1PE\nMPEAzhcqG8i3oZwwl62pjqPja+EvSuoPHf0tJ1rmjWmBt3irShSnuFN69+E4h20d\n2cHVyF4GqF2VdNPYa0lh0cSIsNCJJ5+eyXRHKPcUCKI7pDYdbKZt+8ILlZC5PsSK\nC0XsWIzqSG69Uqkm8c0P07NPmcAnGC3O92uhOrb4ytC2KyHVrNa+Bs6VYlYr3ayq\n5AVfJZGuSxldlyM0N/peEKqz9vok4FoBxxSZGDi9ZDIMjLTpypHOMXi0d8YcClFO\nlmRijJoUF95T+svxE60fdndPlleDKC8OnxvcIbS4OSK0ZqK1SFgTNaIgOniUSY6Q\nV0KM\n-----END CERTIFICATE-----"
	            },
	            "sourceType": "CERTIFICATE_BUNDLE"
	         },
	         "tags": [
	            {
	               "key": "HIDDEN_DUE_TO_SECURITY_REASONS",
	               "value": "HIDDEN_DUE_TO_SECURITY_REASONS"
	            }
	         ]
	      },
	      "responseElements": {
	         "trustAnchor": {
	            "createdAt": "2024-08-01T13:56:39.482702201Z",
	            "enabled": true,
	            "name": "malicious-rolesanywhere-trust-anchor",
	            "notificationSettings": [
	               {
	                  "channel": "ALL",
	                  "configuredBy": "rolesanywhere.amazonaws.com",
	                  "enabled": true,
	                  "event": "CA_CERTIFICATE_EXPIRY",
	                  "threshold": 45
	               },
	               {
	                  "channel": "ALL",
	                  "configuredBy": "rolesanywhere.amazonaws.com",
	                  "enabled": true,
	                  "event": "END_ENTITY_CERTIFICATE_EXPIRY",
	                  "threshold": 45
	               }
	            ],
	            "source": {
	               "sourceData": {
	                  "x509CertificateData": "-----BEGIN CERTIFICATE-----\nMIIE3zCCAsegAwIBAgIJAOZLUn/n7YvYMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNV\nBAYTAkVTMB4XDTIyMDcxMDIxMjgxOVoXDTMyMDcwNzIxMjgxOVowDTELMAkGA1UE\nBhMCRVMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDb0ga7LzegYNXV\noBTY7ByNCtgqAEoZVQAEQAxpWzK4wL4V+TKRRGiP9KQSbMsU35dBuxzg2Ih62dwr\nh6S7vYX4eU8YpGcutrWekzAl+G4GwfbHcwJYt9ALrneFUUWEedYA6BTVG0b+cwIL\nOkVJSlB/4bAVFocwafdnFi3CLsIhXF/Yn90mnug+qsXSWPMZmTXaykiO9+AWV/pO\n/JNS2WLPp4EKUT3CGm12TxBMHG0sWG0xopuj4KXTsyJFELDevSo92ldqyCIJFgG8\nwBmbETxx9TlTPEU6hVkG4MLE2ekkEQK8WVLpZvTGFRrauawMhAzfFV9ZcgIsURy7\nv2/FlYL7OedesimPfGD8M1dkm4yK2dVvUf/HyEL1IB1+3NtAOoifZ5jBBJKaybF0\n/W85asZWVg+yKokFhmQRzu4BFnPhsoTwau+WuySYokbWIEzdW8FljWpwiPlvnqy+\nVJVKdZuzWx12yLzK5srQ4Qcb/tQqkooVASM0PH5ts3PYlf5hRgxqKgCR5lXODxoA\n0aylk6+wC2oBLhvufmwObsOMcxMbPv+EQvzYChL1MRLvEPAmATiE64ZLn8IOu9MG\n9GRC6D/NkLy9LdsPWfzx+W1itrWR3ft/uD/HXILAVc54HejbZGsPsLe7qITDNc7n\nD5zM+orgu67zgRaBOm1kPZbr/vHUFQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYw\nHQYDVR0OBBYEFJNT8WprixUiturSY9GAHXmAcP/RMA8GA1UdEwEB/wQFMAMBAf8w\nDQYJKoZIhvcNAQELBQADggIBAJ1clg4GzHuMxTmpz+riL2klUZEMpJPvy682c0iH\nNlG0f30cNHdSlnhCnx78h3n1xotSM8zZf6+LepCZWCzho5p3Fep7sDumQ+chgdIp\nNApgcGX7tpx+TVjrrwkpxioMSfVFHJ7RMSewumnOXw4NsUQmGJdku8FUR7BWRRiY\nfk0MoQ9nuwjt+RcSz/IKdFTzjI70nPikjSSd0L/ovWk5aXgLcnZpgzv6r4HbafJU\n7dEnP+paZugEUts+SNXr3vkSuiLod7iiOcmQFvtRDFUAn4QonoN/6lDDOGLYsy0J\nrv9GI+Y5VYt6JRGNJq/yCBV1KhhjaWll0kl/UNxIr+hBQ5Vul9SiR3jbbNlRh1PE\nMPEAzhcqG8i3oZwwl62pjqPja+EvSuoPHf0tJ1rmjWmBt3irShSnuFN69+E4h20d\n2cHVyF4GqF2VdNPYa0lh0cSIsNCJJ5+eyXRHKPcUCKI7pDYdbKZt+8ILlZC5PsSK\nC0XsWIzqSG69Uqkm8c0P07NPmcAnGC3O92uhOrb4ytC2KyHVrNa+Bs6VYlYr3ayq\n5AVfJZGuSxldlyM0N/peEKqz9vok4FoBxxSZGDi9ZDIMjLTpypHOMXi0d8YcClFO\nlmRijJoUF95T+svxE60fdndPlleDKC8OnxvcIbS4OSK0ZqK1SFgTNaIgOniUSY6Q\nV0KM\n-----END CERTIFICATE-----\n"
	               },
	               "sourceType": "CERTIFICATE_BUNDLE"
	            },
	            "trustAnchorArn": "arn:aws:rolesanywhere:cn-northsouth-3r:791182566784:trust-anchor/4d07f6a0-1c50-44d3-951b-b68b783daa0a",
	            "trustAnchorId": "4d07f6a0-1c50-44d3-951b-b68b783daa0a",
	            "updatedAt": "2024-08-01T13:56:39.482702201Z"
	         }
	      },
	      "sourceIPAddress": "221.252.237.0",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "rolesanywhere.cn-northsouth-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_e2e652c1-ed4b-4402-b3b0-136ef4c9ace7",
	      "userIdentity": {
	         "accessKeyId": "AKIA3SBEM4QSKES6Z5F9",
	         "accountId": "791182566784",
	         "arn": "arn:aws:iam::791182566784:user/christophe",
	         "principalId": "AIDADMWJD73A3SNMRPEY",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "cn-northsouth-3r",
	      "eventCategory": "Management",
	      "eventID": "aebbe7b5-7cfb-4b00-a30c-48078fedffd8",
	      "eventName": "CreateProfile",
	      "eventSource": "rolesanywhere.amazonaws.com",
	      "eventTime": "2024-08-01T13:56:39Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.10",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "791182566784",
	      "requestID": "4f6be2aa-b5b3-4f95-bad6-5751f3904fbf",
	      "requestParameters": {
	         "durationSeconds": 3600,
	         "enabled": true,
	         "name": "malicious-rolesanywhere-profile",
	         "roleArns": [
	            "arn:aws:iam::791182566784:role/stratus-red-team-trust-anchor-role"
	         ],
	         "tags": [
	            {
	               "key": "HIDDEN_DUE_TO_SECURITY_REASONS",
	               "value": "HIDDEN_DUE_TO_SECURITY_REASONS"
	            }
	         ]
	      },
	      "responseElements": {
	         "profile": {
	            "acceptRoleSessionName": false,
	            "attributeMappings": [
	               {
	                  "certificateField": "x509Issuer",
	                  "mappingRules": [
	                     {
	                        "specifier": "*"
	                     }
	                  ]
	               },
	               {
	                  "certificateField": "x509SAN",
	                  "mappingRules": [
	                     {
	                        "specifier": "DNS"
	                     },
	                     {
	                        "specifier": "URI"
	                     },
	                     {
	                        "specifier": "Name/*"
	                     }
	                  ]
	               },
	               {
	                  "certificateField": "x509Subject",
	                  "mappingRules": [
	                     {
	                        "specifier": "*"
	                     }
	                  ]
	               }
	            ],
	            "createdAt": "2024-08-01T13:56:39.832628281Z",
	            "createdBy": "arn:aws:iam::791182566784:user/christophe",
	            "durationSeconds": 3600,
	            "enabled": true,
	            "name": "malicious-rolesanywhere-profile",
	            "profileArn": "arn:aws:rolesanywhere:cn-northsouth-3r:791182566784:profile/910042eb-8463-427d-8095-6fd60ac303d9",
	            "profileId": "910042eb-8463-427d-8095-6fd60ac303d9",
	            "roleArns": [
	               "arn:aws:iam::791182566784:role/stratus-red-team-trust-anchor-role"
	            ],
	            "updatedAt": "2024-08-01T13:56:39.832628281Z"
	         }
	      },
	      "sourceIPAddress": "221.252.237.0",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "rolesanywhere.cn-northsouth-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_e2e652c1-ed4b-4402-b3b0-136ef4c9ace7",
	      "userIdentity": {
	         "accessKeyId": "AKIA3SBEM4QSKES6Z5F9",
	         "accountId": "791182566784",
	         "arn": "arn:aws:iam::791182566784:user/christophe",
	         "principalId": "AIDADMWJD73A3SNMRPEY",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
