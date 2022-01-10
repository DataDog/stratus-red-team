# Stratus Red team

Stratus Red Team is "Atomic Red Team" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.

## Concepts

- An **Attack Technique** is a granular TTP that has **pre-requisites** infrastructure or configuration.
- An attack technique can be **detonated** to execute it against a live environment
- **Warming up** an attack technique means "making sure its pre-requisites are met, without detonating it"

## How it works

Each attack technique provides a Terraform file for its pre-requisites. When ran, Stratus Red Team instruments Terraform to make sure the pre-requisites are met. You don't need Terraform; Stratus Red Team downloads its own Terraform version, to make sure it does not affect your local Terraform setup.

## Usage

You can list the available techniques using:

```bash
# List all techniques
stratus list

# List all persistence techniques
stratus list --mitre-attack-tactic persistence

# List all AWS tactics
stratus list --platform aws
```

View the detail of a specific technique using:

```bash
$ stratus show aws.exfiltration.ebs-snapshot-shared-with-external-account
Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: Creates an EBS volume and a snapshot.
Detonation: Calls ModifySnapshotAttribute to share the snapshot.
```

You can detonate an attack technique using:

```bash
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```

This will handle warm-up, detonation and clean-up.

Alternatively, you can handle warm-up and detonation independently:

```bash
stratus warmup aws.exfiltration.ebs-snapshot-shared-with-external-account
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account --no-warmup
```

You can detonate an attack technique without cleaning it up, for instance to see which forensics artifacts it leaves:

```
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account --no-cleanup 
```

TODO: `stratus cleanup`

## Supported platforms

- AWS (you need to be authenticated to AWS before running Stratus Red Team)
