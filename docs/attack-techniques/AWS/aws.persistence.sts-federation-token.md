---
title: Generate temporary AWS credentials using GetFederationToken
---

# Generate temporary AWS credentials using GetFederationToken


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Persistence


- Threat Technique Catalog for AWS:
  
    - [Account Manipulation: Additional Cloud Credentials](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html) (T1098.001)
  


## Description


Establishes persistence by generating new AWS temporary credentials through <code>sts:GetFederationToken</code>. The resulting credentials remain functional even if the original access keys are disabled.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM user and generate a pair of access keys.

<span style="font-variant: small-caps;">Detonation</span>: 

- Use the access keys from the IAM user to request temporary security credentials via <code>sts:GetFederationToken</code>.
- Call <code>sts:GetCallerIdentity</code> using these new credentials.

References:

- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
- https://www.crowdstrike.com/en-us/blog/how-adversaries-persist-with-aws-user-federation/
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.sts-federation-token
```
## Detection


Through CloudTrail's <code>GetFederationToken</code> event.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `sts:GetCallerIdentity`

- `sts:GetFederationToken`


??? "View raw detonation logs"

    ```json hl_lines="6 51"

    [
	   {
	      "awsRegion": "ap-isob-east-1r",
	      "eventCategory": "Management",
	      "eventID": "6e882b9d-2af8-4c67-b91f-aeac6a0e5e70",
	      "eventName": "GetFederationToken",
	      "eventSource": "sts.amazonaws.com",
	      "eventTime": "2024-11-30T08:43:17Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "742491224508",
	      "requestID": "e2de7fd1-2a86-4837-b15a-96fff1388061",
	      "requestParameters": {
	         "name": "stratus_red_team",
	         "policy": "{\n\t\t\"Version\": \"2012-10-17\",\n\t\t\"Statement\": [\n\t\t\t{\n\t\t\t\t\"Effect\": \"Allow\",\n\t\t\t\t\"Action\": \"*\",\n\t\t\t\t\"Resource\": \"*\"\n\t\t\t}\n\t\t]\n\t}"
	      },
	      "responseElements": {
	         "credentials": {
	            "accessKeyId": "ASIASTJKC5GCM7ZE6LUP",
	            "expiration": "Nov 30, 2024, 8:43:17 PM",
	            "sessionToken": "IQoJb3JpZ2luX2VjEOH//////////wEaCXVzLWVhc3QtMSJIMEYCIQDzpomGZAmkp4RIzBo4RqVJGEmUNjyA7lHyt1aKfFh8IwIhANX6aS3XpNU319gOolVjEBkNLRmu9dyO8FqoDW5y+HL4KqICCIr//////////wEQABoMMzQ1NTk0NjA3OTQ5IgykqzjqIZ5pQXZgeDEq9gGg9Law7M5zzj/fSvNlo2pgdgHCmA6UW8IevbwXiKbLO5y0dg/sdhsaEUaOvl6i2Fu+xF2p3dvI8SuCJSTH5PEC2ZRgX1TPhzh+0xN7CsCQG2diBitgDQSs+E3P9ED4xDVuTCE9H8IIS/2BuksBI9bQ3z2itKRkVmkC+xpsfyFc98vX0ZLSUKOIpx+iaDNrhiW85Cyt6ezNEyLfX3bukmmIdVIZQ+Tb4tYLvIRKIyp6OFiA3BL48K7nfIAd1EzDhGnlvkZN/70hDxYt8hTKehNXDs2FVKY5u96z0zhsnNGcuhHHa7OEOKg5lLL5QuEzjx6JA+e9qaQwpaCrugY6mAFp1LZ4E15PVqImPSC/wtr+rEU4Dnp+1/6+PNkbxvxYXfqZOfJxRkZtgWtmV7iWapGzA/pVedD4vuHci4Kq2NUTuyA8L7BeKSaEq0FqFi1yrfCYjYsGI3ncxMQQddgiXVXeoWY4c4auGvAHgiJI/PDQPsaa3Sle/gGnok53u8NfNYoBRtASGaJJtGS0ylDxsQVe9InwBxoJnQ=="
	         },
	         "federatedUser": {
	            "arn": "arn:aws:sts::742491224508:federated-user/stratus_red_team",
	            "federatedUserId": "742491224508:stratus_red_team"
	         },
	         "packedPolicySize": 4
	      },
	      "sourceIPAddress": "255.090.254.5",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "sts.ap-isob-east-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "aws-sdk-go-v2/1.32.3 os/linux lang/go#1.23.1 md/GOOS#linux md/GOARCH#amd64 exec-env/grimoire_095724e3-1fa0-4e3e-b68a-e8581d194380 api/sts#1.26.2",
	      "userIdentity": {
	         "accessKeyId": "AKIA6V1GNZTT65XQH36M",
	         "accountId": "742491224508",
	         "arn": "arn:aws:iam::742491224508:user/stratus-red-team-user-federation-user",
	         "principalId": "AIDAN7SEM6PEVTNQR8M4",
	         "type": "IAMUser",
	         "userName": "stratus-red-team-user-federation-user"
	      }
	   },
	   {
	      "awsRegion": "ap-isob-east-1r",
	      "eventCategory": "Management",
	      "eventID": "91529247-c4c4-4793-afc8-d70bbcfe9d19",
	      "eventName": "GetCallerIdentity",
	      "eventSource": "sts.amazonaws.com",
	      "eventTime": "2024-11-30T08:43:18Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "742491224508",
	      "requestID": "037be419-9e9f-42e0-a38f-2a5d2ae1ce65",
	      "requestParameters": null,
	      "responseElements": null,
	      "sourceIPAddress": "255.090.254.5",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "sts.ap-isob-east-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "aws-sdk-go-v2/1.32.3 os/linux lang/go#1.23.1 md/GOOS#linux md/GOARCH#amd64 exec-env/grimoire_095724e3-1fa0-4e3e-b68a-e8581d194380 api/sts#1.26.2",
	      "userIdentity": {
	         "accessKeyId": "ASIASTJKC5GCM7ZE6LUP",
	         "accountId": "742491224508",
	         "arn": "arn:aws:sts::742491224508:federated-user/stratus_red_team",
	         "principalId": "742491224508:stratus_red_team",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-30T08:43:17Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "742491224508",
	               "arn": "arn:aws:iam::742491224508:user/stratus-red-team-user-federation-user",
	               "principalId": "AIDAN7SEM6PEVTNQR8M4",
	               "type": "IAMUser",
	               "userName": "stratus-red-team-user-federation-user"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "FederatedUser"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
