---
title: Launch Unusual EC2 instances
---

# Launch Unusual EC2 instances


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Execution


- Threat Technique Catalog for AWS:
  
    - [Resource Hijacking: Compute Hijacking - EC2 Use](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1496.A008.html) (T1496.A008)
  
    - [Modify Cloud Compute Infrastructure: Create Cloud Instance](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1578.002.html) (T1578.002)
  


## Description


Attempts to launch several unusual EC2 instances (p2.xlarge).

<span style="font-variant: small-caps;">Warm-up</span>: Creates an IAM role that doesn't have permissions to launch EC2 instances. 
This ensures the attempts is not successful, and the attack technique is fast to detonate.

<span style="font-variant: small-caps;">Detonation</span>: Attempts to launch several unusual EC2 instances. The calls will fail as the IAM role does not have sufficient permissions.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.ec2-launch-unusual-instances
```
## Detection


Trough CloudTrail events with the event name <code>RunInstances</code> and error
<code>Client.UnauthorizedOperation</code>. The <code>eventSource</code> will be
<code>ec2.amazonaws.com</code> and the <code>requestParameters.instanceType</code>
field will contain the instance type that was attempted to be launched.

Depending on your account limits you might also see <code>VcpuLimitExceeded</code> error codes.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ec2:RunInstances`

- `sts:AssumeRole`


??? "View raw detonation logs"

    ```json hl_lines="8 70 122"

    [
	   {
	      "awsRegion": "ca-south-3r",
	      "errorCode": "Client.UnauthorizedOperation",
	      "errorMessage": "You are not authorized to perform this operation. User: arn:aws:sts::751353041310:assumed-role/stratus-red-team-ec2lui-role-idtzskbvtd/aws-go-sdk-1722511821294449000 is not authorized to perform: ec2:RunInstances on resource: arn:aws:ec2:ca-south-3r:751353041310:instance/* because no identity-based policy allows the ec2:RunInstances action. Encoded authorization failure message: T-kSWIRFn32_fxSgyNzoE36avE5lRaRniAjDs-OdhlNgyecEbeTN_dCroUmnEqAbDOrevkgWv8iyUzs0XJxEDlAcgDztlJ-QPNokwAE1JUrWPZcLqpsuM6kK46d5jCUvmzpU_Egq-fML4ed58JHxMdyU4Iz1WGOb6S3W3FB5jghu3JqyDR1B8S8qHryW-e8H1ukHarLt7Ogr4rvYezZ3sf_DNCPDjCGLOSI75x4W0X4Wcl9B9eAuhG-hRbB8KG3e-15CmtpWvw5brndvmrK0sAKwOdcyI47AXNV1DKVLKBNjxwNSQB4knWTX00TASAtGZYroYLyadRTdjZO_CwPGIkcI7wiuAPwSJTrri9xF8zPb5ZJ-Zt4-fQRZoge3sWBFv_wRNOcdGXu8MidJV1ev4CJOpwygM9bO68S_ueU2u_MvKE_zRYrMzTYSMiBKpZGZBDiIZGOGOSzJK8aZ5_F0g5CzhI0IzBxBQh2QFLF0eZe6prRdYEnOZ33EDlaD68PhuyM5xFYzNATqG8UlMtNG7eE1XCMpAmLRAv8ZSnE0PUMrg-Z7RhLyIb3p37VxzKKQHVTdEarNtE22jp38CJ0uRZy5eiNmu-O3JMLeB-AuSYFFoGPtH6h2dH2uV4Fj27vJ4...",
	      "eventCategory": "Management",
	      "eventID": "1a4debbb-12e9-4bde-b8c7-ea29002bb2a7",
	      "eventName": "RunInstances",
	      "eventSource": "ec2.amazonaws.com",
	      "eventTime": "2024-08-01T11:30:23Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "900138736586",
	      "requestID": "b663854b-4ebf-4be3-8de0-9c5471904762",
	      "requestParameters": {
	         "blockDeviceMapping": {},
	         "clientToken": "5dd59182-3917-421c-9b2c-7c92954b66ee",
	         "disableApiStop": false,
	         "disableApiTermination": false,
	         "instanceType": "p2.xlarge",
	         "instancesSet": {
	            "items": [
	               {
	                  "imageId": "ami-aCBbfd13bdb1d1E4b",
	                  "maxCount": 10,
	                  "minCount": 1
	               }
	            ]
	         },
	         "monitoring": {
	            "enabled": false
	         },
	         "subnetId": "subnet-0e540f0c7ffb48ae9"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "06.237.252.245",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2.ca-south-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_c8ff220a-7e52-429b-868f-d979123ed2d3",
	      "userIdentity": {
	         "accessKeyId": "ASIA9F6MXE9HSYOXYQOS",
	         "accountId": "900138736586",
	         "arn": "arn:aws:sts::900138736586:assumed-role/stratus-red-team-ec2lui-role-idtzskbvtd/aws-go-sdk-1722511821294449000",
	         "principalId": "AROA13YEHY3VAS32TD341:aws-go-sdk-1722511821294449000",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-08-01T11:30:22Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "900138736586",
	               "arn": "arn:aws:iam::900138736586:role/stratus-red-team-ec2lui-role-idtzskbvtd",
	               "principalId": "AROA13YEHY3VAS32TD341",
	               "type": "Role",
	               "userName": "stratus-red-team-ec2lui-role-idtzskbvtd"
	            }
	         },
	         "type": "AssumedRole"
	      }
	   },
	   {
	      "awsRegion": "ca-south-3r",
	      "eventCategory": "Management",
	      "eventID": "04c882a5-7652-40d1-b44c-83535fc19268",
	      "eventName": "AssumeRole",
	      "eventSource": "sts.amazonaws.com",
	      "eventTime": "2024-08-01T11:30:22Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "900138736586",
	      "requestID": "a8b97cd6-132c-46e7-9305-85f2d79e683d",
	      "requestParameters": {
	         "durationSeconds": 900,
	         "roleArn": "arn:aws:iam::900138736586:role/stratus-red-team-ec2lui-role-idtzskbvtd",
	         "roleSessionName": "aws-go-sdk-1722511821294449000"
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:iam::900138736586:role/stratus-red-team-ec2lui-role-idtzskbvtd",
	            "accountId": "900138736586",
	            "type": "AWS::IAM::Role"
	         }
	      ],
	      "responseElements": {
	         "assumedRoleUser": {
	            "arn": "arn:aws:sts::900138736586:assumed-role/stratus-red-team-ec2lui-role-idtzskbvtd/aws-go-sdk-1722511821294449000",
	            "assumedRoleId": "AROA13YEHY3VAS32TD341:aws-go-sdk-1722511821294449000"
	         },
	         "credentials": {
	            "accessKeyId": "ASIA9F6MXE9HSYOXYQOS",
	            "expiration": "Aug 1, 2024, 11:45:22 AM",
	            "sessionToken": "IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMSJHMEUCIAIdMlsYBfJVLlnMTTUWOX4q3BfLOExnAgLuv5b76q5RAiEA3rFHZ/bap4mdvcTC7M6IzJfWZCdc4Llq3T4CoB3kjXMqqwIIdRABGgw3NTEzNTMwNDEzMTAiDHSUIyjlokGN2fzZcSqIArg4qYntF5grAv0etPkJsxlQnWjCUv5vMvslbaJ/9UP6X8zGTXz/dMdMJ17JdXdn/uGPrJcOXQ6igyD8Wkir0sEb8+SDAm9G7t5xDwSJS5qVz2PTP9tVmUahaBQR5jafJxPh2n8dOSpRAdR8D6iqcfDfAx1afwF8tdjkwcvZvH/rOo7HOGa0xK7U72SryDHkTo5Sz0I3NpGgbC/XZ/q/zFDSfRj11nR/w5ifdLleh+UZrnuHXMU6w2qILZBkX3ucTTwwN8PX+gsXJRgsaVaErMMlGyGyxovJeNuGx7PmV9lAaFeZM2/ZXwQanV6iOmYhQHG3WLuRIz9WvpNYMKCRI2Kn2FuBNJHx/zDO4621BjqdAdOjSmz/25ePFDD5bJYmd21ZQRd4gFjMVSKor2E+SSl6sQ+lY+MOHKEIvID+Afbi66+MnSAHSPvrCpj7f9mkHZWgS4GVoSWXujEUvok1xV+Ef+B/dQE7CjWKqNXgtyEWgWMKI/gQZdKYsvcGAg6tz5qdmbicTRqTwJiLvUwpj5dFdGJeKedOR5P2r/TSV/GHhVjwTSzg7rBgLT8zIkI="
	         }
	      },
	      "sourceIPAddress": "06.237.252.245",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "sts.ca-south-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_c8ff220a-7e52-429b-868f-d979123ed2d3",
	      "userIdentity": {
	         "accessKeyId": "AKIAR7ISFR69YWROPYAN",
	         "accountId": "900138736586",
	         "arn": "arn:aws:iam::900138736586:user/christophe",
	         "principalId": "AIDA32NEE582826ECMV4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "ca-south-3r",
	      "eventCategory": "Management",
	      "eventID": "9a6353be-6cb8-4a0c-ab85-a46dbd3a2b71",
	      "eventName": "AssumeRole",
	      "eventSource": "sts.amazonaws.com",
	      "eventTime": "2024-08-01T11:30:21Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "900138736586",
	      "requestID": "7197a903-38a0-4e24-8683-dc858142b3c8",
	      "requestParameters": {
	         "durationSeconds": 900,
	         "roleArn": "arn:aws:iam::900138736586:role/stratus-red-team-ec2lui-role-idtzskbvtd",
	         "roleSessionName": "aws-go-sdk-1722511821294449000"
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:iam::900138736586:role/stratus-red-team-ec2lui-role-idtzskbvtd",
	            "accountId": "900138736586",
	            "type": "AWS::IAM::Role"
	         }
	      ],
	      "responseElements": {
	         "assumedRoleUser": {
	            "arn": "arn:aws:sts::900138736586:assumed-role/stratus-red-team-ec2lui-role-idtzskbvtd/aws-go-sdk-1722511821294449000",
	            "assumedRoleId": "AROA13YEHY3VAS32TD341:aws-go-sdk-1722511821294449000"
	         },
	         "credentials": {
	            "accessKeyId": "ASIAYY9090UIYYUOIF2U",
	            "expiration": "Aug 1, 2024, 11:45:21 AM",
	            "sessionToken": "IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMSJHMEUCIFzpG0H/IrDX9P0i5y29VWSdkBXkBTwULxR2KkPh4ApdAiEAiHLNdMOheLhjTV5lDnR7oekWR9V+zoDdU90CcpsOup0qqwIIdRABGgw3NTEzNTMwNDEzMTAiDK3uxtzFnKLcVORn9iqIAqQXShn68h/gmprileycyOQFlWvnjmy3JfNIoxpWT7miaEUekUaAVn9qGLQal+2Hyz4mqucWSFP4WCbDL+e5iS1xSz+oMowhtVvThjHV1AmKqxhivS1aoPOsy/P+NrxOyWSPyKuxyOn4khyFjsqDKc221zk5OFx+FqU+77es30KeJT4tJuRzwly679cnX9uUq0Y57yuIaHfAPFVy10EBeajT9wjI2/K9QJCcqKsshspDBRORU5PYiGJnCrcXy2SmumtW6EvH23kIUxYXE+Jv6aTrSCqo1kQDUvP+xYIxBYKR4Kn4zcVZUTgZC3k+plWaRThN/tSfA0aI67O61NQCn/Y0UUL0+5j0kTDN4621BjqdAay4li3+cvLrvgpNdyIMex2CAQbDOKEDCKe00MpLPka3vIDPDANof9D9SPJaynXl7b3t+fKxhMRo8MGyh/37wYhrD26qPAzbFA+Av75KyjEigzAsEyBYhi1Ix2nIYjm9jei10p0yiH1QSGerutzp1UQanzfgyzMpAtVJzy99kRFVKHE8j/rP5jc+iZFNdcDvYbs0tl9bP7kUFNDlVXg="
	         }
	      },
	      "sourceIPAddress": "06.237.252.245",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "sts.ca-south-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_c8ff220a-7e52-429b-868f-d979123ed2d3",
	      "userIdentity": {
	         "accessKeyId": "AKIAR7ISFR69YWROPYAN",
	         "accountId": "900138736586",
	         "arn": "arn:aws:iam::900138736586:user/christophe",
	         "principalId": "AIDA32NEE582826ECMV4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
