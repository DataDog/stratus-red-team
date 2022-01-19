# Backdoor Lambda Function Through Resource-Based Policy

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by backdooring a lambda function to allow its invocation from an external AWS account.

Warm-up: Create the pre-requisite Lambda function.

Detonation: Modify the Lambda function resource-base policy to allow access from an external AWS account.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.backdoor-lambda-function
```