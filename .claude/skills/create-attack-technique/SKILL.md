---
name: create-attack-technique
description: >
  Create or review Stratus Red Team attack techniques. Use when asked to add, create,
  or implement a new attack technique for AWS, Azure, GCP, Entra ID, EKS, or Kubernetes
  in the stratus-red-team project. Also use when reviewing PRs or code that implements
  attack techniques — the guidelines serve as a review checklist.
---

## Overview

Each attack technique is composed of two files, which should be stored in `v2/internal/attacktechniques/<platform>/<mitre-attack-tactic>/<name>` (e.g., `v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-delete/`):
- `main.go`, containing the imperative attack logic
- most of the time, `main.tf` containing prerequisite infrastructure.

The lifecycle of an attack technique in Stratus Red Team is:
- COLD
- WARM: The prerequisite infrastructure is ready.
- DETONATED: The attack technique was detonated.

## Guiding principles

- An attack technique should be granular, meaning that it should emulate a single step of an attack.
  - Good: Share an EBS snapshot with an external AWS account.
  - Bad: Use an IAM access key to perform privilege escalation, run discovery commands, take an EBS snapshot of an instance, share the EBS snapshot with an external AWS account.

- Techniques should emulate plausible and documented attacker behavior
- An attack technique should not be dependent on the state of the cloud environment it's run against.

## Instructions

When **creating** a new technique, follow the workflow below step by step. When **reviewing** a PR or existing technique, use the guidelines below as a checklist to verify correctness and consistency.

### Create the prerequisite infrastructure in the Terraform file

#### Provider versions and configurations to use

See [references/provider-configs.md](references/provider-configs.md) for the required Terraform provider blocks for each platform (AWS, Azure, Entra ID, GCP, Kubernetes).

When you're done, format your Terraform file using:

```bash
terraform fmt -write v2/internal/attacktechniques/<platform>/<tactic>/<name>/main.tf
```

#### Use of outputs

- Any outputs you defined will be passed to the Go file, which can consume them from the `detonate` and `revert` functions, e.g. `params["output_name"]`.
- The value of the `display` output is displayed back to the user on the CLI. Example:

```hcl
output "display" {
  value = format("%s Secrets Manager secrets ready", local.num_secrets)
}
```

### Write the Go detonation code

#### Skeleton

See `assets/sample-attack-technique.go`

#### Guidelines for Go detonation code

- As much as possible, use the official cloud providers' Go SDK.
- For AWS, use the AWS SDK for Go v2.
- Leverage methods from the injected 'providers' objects to instantiate cloud providers' SDK. Examples below
  - AWS CloudTrail: `cloudtrail.NewFromConfig(providers.AWS().GetConnection())`
  - Azure Network: `client, err := armnetwork.NewClientFactory(providers.Azure().SubscriptionID, providers.Azure().GetCredentials(), providers.Azure().ClientOptions)`
  - GCP IAM: `service, err := iam.NewService(ctx, providers.GCP().Options())`

#### Error handling

- Always return errors from `detonate` and `revert` — never use `log.Fatalf()`.
- Use `fmt.Errorf("failed to <action>: %w", err)` for error wrapping.
- Log the operation being attempted before making the API call with `log.Println`.

#### Revert function

If the detonation is reversible, implement a `revert` function that undoes the changes made by `detonate`. This allows the technique to be cleaned up after use. The `revert` function has the same signature as `detonate`: `func revert(params map[string]string, providers stratus.CloudProviders) error`. See `assets/sample-attack-technique.go` for an example.

#### Guideline for documentation fields

* `ID` should always be of the form `platform.mitre-attack-tactic.name`, e.g. `aws.defense-evasion.cloudtrail-delete`
* `FriendlyName` should always start with a verb, and be in the infinitive form.
  * Bad: `S3 ransomware`, `Creates S3 ransomware`
  * Good: `Simulate S3 ransomware`
* `Description` should contain at least an intro sentence and a Warm-up, Detonation, References section. "References" should ideally be examples of usage/sightings of this technique in the wild, or relevant cloud provider documentation. Example:

```
Establishes persistence by creating a service account key on an existing service account.

Warm-up:

- Create a service account

Detonation:

- Create a new key for the service account

References:

- https://expel.com/blog/incident-report-spotting-an-attacker-in-gcp/
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
```

* `Detection` should describe how to detect this technique, including relevant CloudTrail/audit log event names and any managed detection rules (e.g. GuardDuty finding types). Use HTML for formatting since it renders in the docs. Example:

```
Identify when a CloudTrail trail is disabled, through CloudTrail's <code>StopLogging</code> event.

GuardDuty also provides a dedicated finding type, <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled">Stealth:IAMUser/CloudTrailLoggingDisabled</a>.
```

* `IsIdempotent`: set to `true` if the detonation can be called multiple times without side effects.

#### Add your new Go file to the imported attack techniques

Add a new import corresponding to your new Go file in `v2/internal/attacktechniques/main.go`.

#### Format your go code

Run:

```
cd v2 # if you're not already in there
go fmt ./...
```

### Autogenerate docs

```
make docs
```

## DON'T

- Don't persist anything in the Go detonation code. The revert and detonate methods are called in different runs, so they cannot use variables to share state.
