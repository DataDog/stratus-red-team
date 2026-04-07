# Example: S3 remote state with multi-cloud attacks

This example stores all state (Terraform tfstate, technique lifecycle, outputs, variables) in an S3 bucket, while running attacks against a separate AWS account and a GCP project.

Three sets of credentials are involved:

| Purpose                             | Source                                   | Account/Project                         |
| ----------------------------------- | ---------------------------------------- | --------------------------------------- |
| State bucket (S3)                   | Explicit (`STATE_*` env vars)            | AWS account hosting the bucket          |
| AWS target (Terraform + detonation) | Environment (`AWS_*` env vars)           | AWS account where resources are created |
| GCP target (Terraform + detonation) | Environment (`gcloud auth` / `GOOGLE_*`) | GCP project where resources are created |

## 1. Create the state bucket

Authenticate against the AWS account that will host the state bucket:

```bash
# Replace with your auth method
aws-vault exec <state-bucket-account-admin>

aws s3 mb s3://<your-org>-stratus-state --region us-east-1
```

## 2. Get state bucket credentials

Export credentials for the bucket account as `STATE_*` variables. If using aws-vault, it already injects session credentials:

```bash
eval "$(aws-vault exec <state-bucket-account-admin> -- env | grep ^AWS_ | sed 's/^AWS_/export STATE_AWS_/')"

# Verify
echo $STATE_AWS_ACCESS_KEY_ID
```

Or with an explicit assume-role (useful when not using aws-vault):

```bash
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::<bucket-account-id>:role/<role-name> \
  --role-session-name stratus-state \
  --query Credentials --output json)

export STATE_AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export STATE_AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export STATE_AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)
```

## 3. Set target credentials

**AWS target** — authenticate against the account where attack resources will be deployed:

```bash
# Replace with your auth method
aws-vault exec <target-aws-account-admin>

# Verify
aws sts get-caller-identity
```

**GCP target** — authenticate against the project where attack resources will be deployed:

```bash
gcloud auth application-default login
export GOOGLE_PROJECT=<your-gcp-project-id>
```

## 4. Run

```bash
export STATE_BUCKET_NAME=<your-org>-stratus-state
go run main.go
```

Expected output:

```
State bucket identity: arn:aws:sts::111111111111:assumed-role/...
=== AWS technique ===
Technique: aws.defense-evasion.cloudtrail-stop (correlation: ...)
Warming up (target credentials from environment)
...
Warmup complete
Press enter to detonate aws.defense-evasion.cloudtrail-stop
...
=== GCP technique ===
Technique: gcp.defense-evasion.delete-logging-sink (correlation: ...)
...
```

## 6. Cleanup

```bash
# Remove the state bucket (after all techniques are cleaned up)
aws-vault exec <state-bucket-account-admin>
aws s3 rb s3://<your-org>-stratus-state --force
```
