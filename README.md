# Stratus Red team

Stratus Red Team is "[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.

## Installation

### Building locally

``` bash
make
./bin/stratus --help
```

### Docker

```bash
docker build . -t stratus-red-team
docker run --rm stratus-red-team list
```

### Running locally for development

```bash
go run cmd/stratus/*.go list
```