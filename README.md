# Stratus Red team

Stratus Red Team is "Atomic Red Team" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.

## Concepts

- An **Attack Technique** is a granular TTP that has **pre-requisites** infrastructure or configuration.
- An attack technique can be **detonated** to execute it against a live environment
- **Warming up** an attack technique means "making sure its pre-requisites are met, without detonating it"

## How it works

Each attack technique provides a Terraform file for its pre-requisites. When ran, Stratus Red Team instruments Terraform to make sure the pre-requisites are met. You don't need Terraform; Stratus Red Team downloads its own Terraform version, to make sure it does not affect your local Terraform setup.

## Usage

```
Usage:
  stratus-red-team [command]

Available Commands:
  cleanup     Cleans up any leftover infrastructure or configuration from a TTP.
  completion  Generate the autocompletion script for the specified shell
  detonate    Detonate one or multiple attack techniques
  help        Help about any command
  list        List attack techniques
  show        Displays detailed information about an attack technique.
  status      Display the status of TTPs.
  version     Display the current CLI version
  warmup      "Warm up" an attack technique by spinning up the pre-requisite infrastructure or configuration, without detonating it

Flags:
  -h, --help   help for stratus-red-team
```

## Examples

List available TTPs using:

```bash
# List all techniques
stratus list

# List all persistence techniques
stratus list --mitre-attack-tactic persistence

# List all AWS tactics
stratus list --platform aws
```

View the detail of a specific technique:

```bash
$ stratus show aws.exfiltration.ebs-snapshot-shared-with-external-account
Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: Creates an EBS volume and a snapshot.
Detonation: Calls ModifySnapshotAttribute to share the snapshot.
```

Detonate an attack technique using:

```bash
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```

This will handle warm-up, detonation and clean-up.

Alternatively, you can handle warm-up and detonation independently:

```bash
stratus warmup aws.exfiltration.ebs-snapshot-shared-with-external-account
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```

You can detonate an attack technique without cleaning it up, for instance to see which forensics artifacts it leaves behind:

```
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account --no-cleanup 
```

Manual cleanup can be done through:

```bash
stratus cleanup aws.exfiltration.ebs-snapshot-shared-with-external-account
```

At any time, you can view the state of the TTPs:

```bash
stratus status

+------------------------------------------------------------+-----------+
| TECHNIQUE                                                  | STATUS    |
+------------------------------------------------------------+-----------+
| aws.exfiltration.ebs-snapshot-shared-with-external-account | WARM      |
| aws.persistence.backdoor-iam-user                          | DETONATED |
| aws.persistence.backdoor-iam-role                          | WARM      |
| aws.persistence.malicious-iam-user                         | COLD      |
+------------------------------------------------------------+-----------+
```

## Supported platforms

- AWS (you need to be authenticated to AWS before running Stratus Red Team)
