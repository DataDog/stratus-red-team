# Contributing

We welcome pull requests, contributions and feedback! For any bug report or feedback, [open an issue](https://github.com/DataDog/stratus-red-team/issues/new/choose).

## Contributing to a new attack technique

Stratus Red Team is opinionated in the attack techniques it packages - see [Philosophy](./attack-techniques/philosophy.md). Feel free to open an issue to discuss ideas about new attack techniques. You can see the current backlog using the GitHub issue label [`kind/new-technique`](https://github.com/DataDog/stratus-red-team/issues?q=is%3Aissue%20is%3Aopen%20label%3Akind%2Fnew-technique%20).

To create a new attack technique:

1. Create a new folder under `v2/internal/attacktechniques/your-cloud/your-mitre-attack-tactic/your-attack-name`
2. Create a `main.go` file that contains the detonation (and optionally, the revert) behavior. See for example [cloudtrail-stop/main.go](https://github.com/DataDog/stratus-red-team/blob/main/v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-stop/main.go)
3. If your attack technique contains pre-requisites, create a `main.tf` file
4. Add your attack technique to the imports of `v2/internal/attacktechniques/main.go`

To generate the logs dataset using [Grimoire](https://github.com/DataDog/grimoire):

1. Install Grimoire
2. Run the following to detonate the attack and retrieve CloudTrail logs:

```bash
# Build your local Stratus Red Team version
make

# Open a shell in which Grimoire collects the cloud audit logs
grimoire shell -o /tmp/your-attack.json
```

Then, inside that shell, run the whole lifecycle with Grimoire's detonation ID as the correlation ID:

```bash
export STRATUS_RED_TEAM_CORRELATION_ID=$GRIMOIRE_DETONATION_ID
./bin/stratus warmup your-attack
./bin/stratus detonate your-attack
./bin/stratus cleanup your-attack
exit  # Grimoire then looks for the events your commands generated
```

!!! warning

    Export the correlation ID for **every** command of the lifecycle, not just `detonate`. It
    determines where Stratus Red Team stores the execution's state, so a `detonate` that does not
    see the same value as its `warmup` provisions a second, separate set of resources. See
    [Concurrent executions](./user-guide/concurrent-executions.md).

Setting the correlation ID is what lets Grimoire find the detonation events: Stratus Red Team
replaces the user agent of the AWS calls it makes with `stratus-red-team_<correlation-id>`, so
without it those calls would not carry Grimoire's identifier. Note that `warmup` and `cleanup` run
inside the collection window too, so the dataset also contains their events - keep only the ones
produced by the detonation.

3. Anonymize the logs using [LogLicker](https://github.com/Permiso-io-tools/LogLicker):

```bash
# Note: see https://github.com/Permiso-io-tools/LogLicker/issues/5 for a currently necessary patch
../LogLicker/venv/bin/python ../LogLicker/RunLogLicker.py rawtext -ifp /tmp/your-attack.json -ofp ./docs/detonation-logs/your-attack.json
```

4. Generate the docs:

```bash
make docs
```

## Contributing to the core of Stratus Red Team

When contributing to the core of Stratus Red Team (i.e. anything that is not a new attack technique), include unit tests if applicable.