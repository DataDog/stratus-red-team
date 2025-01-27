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

# Generate cloud audit logs
./bin/stratus warmup your-attack
grimoire shell --command 'export STRATUS_RED_TEAM_DETONATION_ID=$GRIMOIRE_DETONATION_ID; ./bin/stratus detonate your-attack' -o /tmp/your-attack.json
# Press Ctrl+C once you see the expected events
./bin/stratus cleanup your-attack
```

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