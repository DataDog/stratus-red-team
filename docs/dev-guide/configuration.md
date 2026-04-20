# Configuration System

Stratus Red Team has a configuration system that lets users customize how techniques create resources (namespace, images, tolerations, etc.). This page explains how to consume the configuration in your technique.

For now, only Kubernetes-specific keys are available, but it can be easily extended to handle other providers.

## In Terraform (recommended for prerequisites)

A shared `variable "config"` is automatically injected alongside your `main.tf` at warmup time. You don't need to declare it — just reference it:

```hcl
locals {
  namespace = var.config.kubernetes.namespace != "" ? var.config.kubernetes.namespace : kubernetes_namespace.ns[0].metadata[0].name
  image     = var.config.kubernetes.pod.image != "" ? var.config.kubernetes.pod.image : "alpine:3.15"
}

resource "kubernetes_pod" "pod" {
  spec {
    node_selector = var.config.kubernetes.pod.node_selector
    dynamic "toleration" {
      for_each = var.config.kubernetes.pod.tolerations
      content {
        key      = toleration.value.key
        operator = toleration.value.operator
        value    = toleration.value.value
        effect   = toleration.value.effect
      }
    }
    # ...
  }
}
```

The variable definition (in `pkg/stratus/config/config.tf`) provides defaults for all fields, so your Terraform code works with or without a user config file.

## In Go (for techniques that create resources at detonation time)

For techniques that create resources in Go code (not Terraform), use `Apply[Resource]Config` (for K8S pod resources, it's `ApplyPodConfig`) to apply the user's configuration:

```go
func detonate(params map[string]string, providers stratus.CloudProviders) error {
    podSpec := &v1.Pod{ /* ... your base pod spec ... */ }
    providers.K8s().ApplyPodConfig(techniqueID, podSpec)
    // podSpec now has the user's tolerations, labels, image, etc.
}
```

## Adding new config keys

To add support for a new configuration section (e.g. AWS-specific config):

1. Add the new properties to the JSON schema (`pkg/stratus/config/config.schema.json`)
2. Add the corresponding Terraform variable type to `pkg/stratus/config/config.tf`
3. Use **snake_case** for all config keys — this ensures consistency between YAML, Terraform, and Go

The configuration is validated against the JSON schema at startup, so users get immediate feedback on typos or invalid structure.
