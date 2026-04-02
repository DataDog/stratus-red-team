# Example: injecting explicit cloud credentials

This example injects explicit AWS credentials into the runner for the detonation and revert phases, instead of relying on the default credential chain.

> **Current limitation:** injected credentials are only used by the Detonate and Revert functions (Go SDK calls). Terraform warmup and cleanup still use the credentials from the environment. This means both sets of credentials must have access to the same account. A future change will allow forwarding injected credentials to Terraform as well.

## 1. Create a test role

Authenticate as an admin in the target account, then create a role with the permissions needed for the detonation:

```bash
# Authenticate as admin
aws-vault exec sso-sbx-ase-futz-account-admin

# Get your current account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create the role, trusting the same account
aws iam create-role \
  --role-name stratus-attacker \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'$ACCOUNT_ID':root"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach a minimal policy for the cloudtrail-stop technique
# (StopLogging for detonate, StartLogging for revert)
aws iam put-role-policy \
  --role-name stratus-attacker \
  --policy-name cloudtrail-stop \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:StartLogging"
      ],
      "Resource": "*"
    }]
  }'
```

## 2. Assume the role and export credentials

```bash
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/stratus-attacker \
  --role-session-name stratus-test \
  --query Credentials \
  --output json)

export ATTACK_AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export ATTACK_AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export ATTACK_AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)
```

## 3. Run the example

The admin credentials from aws-vault drive Terraform (creating the CloudTrail trail and S3 bucket). The injected credentials drive the detonation (`cloudtrail:StopLogging`) and revert (`cloudtrail:StartLogging`).

```bash
go run main.go
```

## 4. Cleanup

```bash
aws iam delete-role-policy --role-name stratus-attacker --policy-name cloudtrail-stop
aws iam delete-role --role-name stratus-attacker
```
