# Stratus Red Team

Stratus Red Team is a CLI tool and Go library that allows you to easily detonate granular, real-world cloud attack techniques.

## Guidelines for creating new attack techniques

When you need to create or update new attack techniques, use the `create-attack-technique` skill.

## Testing and developing locally

To run locally:
- `cd v2/`
- `go run cmd/stratus/*.go COMMAND` (e.g. `go run cmd/stratus/*.go list` or `go run cmd/stratus/*.go detonate aws.persistence.admin-iam-user`)

To run unit tests, run `make test`.

To automatically generate attack technique documentation, use `make docs`.

## DON'T

- Don't directly change auto-generated documentation in `docs/attack-techniques/`.