# Stratus Red team

[![Tests](https://github.com/DataDog/stratus-red-team/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/stratus-red-team/actions/workflows/test.yml) [![release](https://github.com/DataDog/stratus-red-team/actions/workflows/release.yml/badge.svg)](https://github.com/DataDog/stratus-red-team/actions/workflows/release.yml)

Stratus Red Team is "[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)™" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.

## Getting Started

Stratus Red Team is a self-contained Go binary.

See the documentation at **[stratus-red-team.cloud](https://stratus-red-team.cloud/)**:
- [Stratus Red Team Concepts](https://stratus-red-team.cloud/user-guide/getting-started/#concepts)

- [Installing Stratus Red Team](https://stratus-red-team.cloud/user-guide/getting-started/#installation) - Homebrew formula, Docker image and pre-built binaries available

- [Available Attack Techniques](https://stratus-red-team.cloud/attack-techniques/list/), mapped to MITREA ATT&CK

## Development

### Building locally

``` bash
make
./bin/stratus --help
```

### Running locally

```bash
go run cmd/stratus/*.go list
```

### Running the tests

```bash
make test
```

### Building the documentation

For local usage:
```
make docs

pip install mkdocs-material
mkdocs serve
```
