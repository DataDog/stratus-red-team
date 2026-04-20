# Terraform Provider Configurations

Use the following provider blocks depending on the target platform.

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

## Azure

```hcl
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.8.0"
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