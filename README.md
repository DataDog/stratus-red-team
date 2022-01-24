# Stratus Red team

[![Tests](https://github.com/DataDog/stratus-red-team/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/stratus-red-team/actions/workflows/test.yml) [![release](https://github.com/DataDog/stratus-red-team/actions/workflows/release.yml/badge.svg)](https://github.com/DataDog/stratus-red-team/actions/workflows/release.yml)

Stratus Red Team is "[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)™" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.

<p align="center">
  <a href="https://github.com/DataDog/stratus-red-team/raw/main/docs/demo.gif">
    <img src="./docs/demo.gif" alt="Terminal recording" />
  </a>
</p>

## Getting Started

Stratus Red Team is a self-contained Go binary.

See the documentation at **[stratus-red-team.cloud](https://stratus-red-team.cloud/)**:
- [Stratus Red Team Concepts](https://stratus-red-team.cloud/user-guide/getting-started/#concepts)

- [Installing Stratus Red Team](https://stratus-red-team.cloud/user-guide/getting-started/#installation) - Homebrew formula, Docker image and pre-built binaries available

- [Available Attack Techniques](https://stratus-red-team.cloud/attack-techniques/list/), mapped to MITREA ATT&CK

## Installation

- Mac OS:

```
brew tap datadog/stratus-red-team
brew install datadog/stratus-red-team/stratus-red-team
```

- Linux / Windows / Mac OS: Download one of the [pre-built binaries](https://github.com/datadog/stratus-red-team/releases).

- Docker:

```
docker pull ghcr.io/datadog/stratus-red-team
docker run --rm ghcr.io/datadog/stratus-red-team
```

## Using Stratus Red Team as a Go Library

See [Examples](./examples) and [Programmatic Usage](https://stratus-red-team.cloud/user-guide/programmatic-usage/).

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
pip install mkdocs-material mkdocs-awesome-pages-plugin

make docs
mkdocs serve
```

### Acknowledgments

Maintainer: [@christophetd](https://twitter.com/christophetd)

Similar projects and inspiration (see [how Stratus Red Team compares](https://stratus-red-team.cloud/comparison/)):
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary
- [Leonidas](https://github.com/FSecureLABS/leonidas) by F-Secure
- [pacu](https://github.com/RhinoSecurityLabs/pacu) by Rhino Security Labs
- [Amazon GuardDuty Tester](https://github.com/awslabs/amazon-guardduty-tester)
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs
