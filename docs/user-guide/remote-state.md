# Remote State (S3)

By default, Stratus Red Team stores all state locally in `~/.stratus-red-team/`. This includes Terraform state files, technique lifecycle state, and outputs.

For team usage or when running Stratus Red Team in ephemeral environments (CI/CD, containers), you can configure an S3 bucket as a remote state backend. This stores all state centrally, allowing multiple users or pods to share state for the same techniques.

## Configuration

Remote state requires a bucket name and region. These can be set via:

1. **CLI flags** (hidden, for scripting): `--state-bucket` and `--state-bucket-region`
2. **Environment variables**: `STRATUS_STATE_BUCKET` and `STRATUS_STATE_BUCKET_REGION`
3. **Config file** (`~/.stratus-red-team/config.yaml` or `STRATUS_CONFIG_PATH`):

```yaml
state:
  bucket: myorg-stratus-state
  region: us-east-1
```

If no bucket is configured, Stratus Red Team uses local state (the default behavior).

## Credentials

The state bucket may live in a different AWS account than the one used for detonation. Credentials for the bucket are resolved separately from the target account credentials:

| Priority | Method                      | Environment variable                                                                                        |
| -------- | --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 1        | AWS named profile           | `STRATUS_STATE_BUCKET_PROFILE`                                                                              |
| 2        | Explicit static credentials | `STRATUS_STATE_AWS_ACCESS_KEY_ID`, `STRATUS_STATE_AWS_SECRET_ACCESS_KEY`, `STRATUS_STATE_AWS_SESSION_TOKEN` |
| 3        | Default credential chain    | _(same as target account — a warning is logged)_                                                            |

!!! note

    The target account credentials used by Terraform to create resources and by the detonation code can be set "as usual" (AWS_* env var for instance) as we just wrap the AWS SDK

## Bucket auto-creation

If the bucket does not exist, Stratus Red Team creates it automatically with [versioning enabled](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) (recommended for Terraform state).

!!! warning

    S3 bucket names are globally unique. Use a name specific to your organization to avoid collisions.

## Example: team of pentesters sharing state

```bash
# One-time setup: create a config file
cat > ~/.stratus-red-team/config.yaml <<EOF
state:
  bucket: myorg-stratus-state
  region: us-east-1
EOF

# Authenticate against the state bucket account
export STRATUS_STATE_BUCKET_PROFILE=myorg-security-tooling

# Authenticate against the target account
aws-vault exec sso-myorg-test-account

# Use Stratus Red Team as usual — state goes to S3 transparently
stratus detonate aws.defense-evasion.cloudtrail-stop
stratus status aws.defense-evasion.cloudtrail-stop
stratus cleanup aws.defense-evasion.cloudtrail-stop
```

Any team member with access to the same bucket and target account can see technique state and clean up resources, even from a different machine.

## Example: ephemeral environments (CI/CD)

```bash
export STRATUS_STATE_BUCKET=myorg-stratus-state
export STRATUS_STATE_BUCKET_REGION=us-east-1
export STRATUS_STATE_AWS_ACCESS_KEY_ID=...     # bucket account creds
export STRATUS_STATE_AWS_SECRET_ACCESS_KEY=...
export STRATUS_STATE_AWS_SESSION_TOKEN=...

# Target account creds (standard AWS env vars)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

stratus detonate aws.defense-evasion.cloudtrail-stop --cleanup
```

## Programmatic usage

When using Stratus Red Team as a Go library, use `WithS3Backend` to configure remote state:

```go
import (
    "github.com/aws/aws-sdk-go-v2/config"
    stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
)

// Build an aws.Config for the bucket account
bucketCfg, _ := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))

runner := stratusrunner.NewRunner(
    technique,
    stratusrunner.StratusRunnerNoForce,
    stratusrunner.WithS3Backend(stratusrunner.S3BackendConfig{
        BucketName: "myorg-stratus-state",
        Region:     "us-east-1",
        AWSConfig:  bucketCfg,
    }),
)
```

See the [s3-remote-state example](https://github.com/DataDog/stratus-red-team/tree/main/examples/s3-remote-state) for a complete working example.
