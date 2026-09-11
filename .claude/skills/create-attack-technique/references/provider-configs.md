# Terraform Provider Configurations

Use the following provider blocks depending on the target platform.

A `variable "correlation"` block is **automatically injected** alongside every technique's `main.tf` at warmup time — do not declare it yourself. It provides `var.correlation.id` (full UUID) and `var.correlation.short` (8-char short form). Embed `var.correlation.short` in all resource names for concurrent-detonation support. See the `create-attack-technique` skill for details.

## AWS / EKS

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.54.0, < 5.0.0" # 4.54.0 at least is required for proper AWS SSO support, see #626
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
  default_tags {
    tags = {
      StratusRedTeam = true
    }
  }
}
```

For AWS techniques that use `var.config.aws.prefix`, the prefix is schema-validated to a maximum of 17 characters (see `config.schema.json`). Keep the technique's base name plus resource suffix short enough that a 17-char prefix, the 8-char `var.correlation.short`, and the suffix all fit within the provider's name-length limit (64 chars for IAM/Lambda, 63 for S3). See [docs/dev-guide/configuration.md](../../../../docs/dev-guide/configuration.md) for details.

## Azure

```hcl
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
  }
}

provider "azurerm" {
  features {}
}
```

## Entra ID

```hcl
terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.53.1"
    }
  }
}
```

## GCP

```hcl
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}
```

## Kubernetes

```hcl
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.7.1"
    }
  }
}
```
