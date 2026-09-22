# Concurrent Executions

By default, Stratus Red Team keeps the state of an attack technique in a single directory per
technique, `$HOME/.stratus-red-team/<technique-id>`. Two executions of the *same* technique would
share that directory, and therefore share one Terraform state: the second execution reuses the
resources of the first, and whichever one is cleaned up first destroys the resources the other is
still using.

Setting a correlation ID isolates an execution. Its state is then stored one level deeper, under
`$HOME/.stratus-red-team/<technique-id>/<correlation-id>`, so each execution gets its own Terraform
state.

```bash
export STRATUS_RED_TEAM_CORRELATION_ID=$(uuidgen)
stratus detonate aws.persistence.iam-backdoor-user
stratus cleanup aws.persistence.iam-backdoor-user
```

The same correlation ID must be used for every command of an execution: it is what allows
`detonate`, `revert` and `cleanup` to find the state that `warmup` wrote. When using the Go library,
pass it with `runner.WithCorrelationID(id)` instead.

`stratus status` follows the same rule. With the correlation ID set it reports on that execution;
without it, it reports on the flat layout, so an isolated execution shows up as `COLD`:

```bash
stratus status aws.persistence.iam-backdoor-user                              # COLD
STRATUS_RED_TEAM_CORRELATION_ID=$ID stratus status aws.persistence.iam-backdoor-user   # WARM
```

Until `status` can list every execution of a technique, keep track of the correlation IDs you
detonate with, or clean up with the same ID you used to warm up.

If you do not set a correlation ID, nothing changes: Stratus Red Team generates one for telemetry
but keeps using the single directory per technique, and commands find each other's state without
you having to thread anything between them.

## Running the same technique concurrently

Isolating the state is necessary but not always sufficient. Attack techniques whose Terraform
creates resources with a fixed name still collide in the cloud provider, because two executions
would ask for the same resource name. In that case the second execution fails at warm-up with an
"already exists" error from the provider -- and, importantly, the first execution is unaffected:
the two no longer share a Terraform state, so cleaning up one cannot destroy the other's resources.

Attack techniques that embed `var.correlation.short` in their resource names can run concurrently.
This is an 8-character form of the correlation ID, short enough for the tightest cloud naming
limits:

```hcl
locals {
  resource_prefix = "stratus-red-team-my-technique-${var.correlation.short}"
}
```

The full correlation ID remains available as `var.correlation.id`, and in Go through
`stratus.CorrelationShortID(providers.AWS().UniqueCorrelationId)`.

## Provider cache

Since each execution has its own Terraform working directory, provider plugins are shared through a
cache at `$HOME/.stratus-red-team/plugin-cache` instead of being downloaded once per execution.

!!! warning "The shared provider cache is not concurrency safe"

    Terraform does not guarantee that its provider plugin cache is safe when `terraform init` runs
    concurrently. Treat the cache as unsafe whenever two Terraform lifecycles can overlap,
    including across separate Stratus Red Team processes. Stratus Red Team serializes `terraform
    init` only within a process; that does not make the shared cache safe while another Terraform
    process is using a provider. Concurrent use can fail with errors such as `text file busy`. See
    [Terraform's provider-cache documentation](https://developer.hashicorp.com/terraform/cli/config/config-file#provider-plugin-cache).

### Disable the shared provider cache

For concurrent detonations, disable the cache by setting `TF_PLUGIN_CACHE_DIR` to an explicitly
empty value before starting Stratus Red Team:

```bash
export TF_PLUGIN_CACHE_DIR=""
```

In Kubernetes, set the container environment variable to an empty string:

```yaml
- name: TF_PLUGIN_CACHE_DIR
  value: ""
```

An **unset** variable retains Stratus Red Team's default shared cache. An explicitly empty variable
opts out of that default, so Terraform installs providers in each execution's own working directory
instead. This trades provider-download reuse for isolation and concurrency safety.

If your Terraform CLI configuration file also sets `plugin_cache_dir`, remove that setting: an empty
environment variable does not override a cache directory configured in `.terraformrc` or
`TF_CLI_CONFIG_FILE`.

## Upgrading from a version without execution isolation

Earlier versions accepted a correlation ID but ignored it when deciding where to store state, so
everything lived in the flat `<technique-id>` directory. When Stratus Red Team finds state there
that belongs to the correlation ID you passed, it moves it into the execution's directory
automatically, and the upgrade needs nothing from you.

Two cases are not migrated automatically:

- State written before Stratus Red Team v2.32.0, which did not record the correlation ID alongside
  the state. There is nothing to match it against.
- State whose recorded correlation ID differs from the one you passed, which by definition belongs
  to another execution.

In both cases the state is still reachable: run the command **without** a correlation ID
(`stratus cleanup <technique-id>`), which resolves to the flat directory and cleans it up.
