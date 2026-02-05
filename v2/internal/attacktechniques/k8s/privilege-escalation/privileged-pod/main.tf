terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.7.1"
    }
  }
}

variable "namespace" {
  description = "Kubernetes namespace to use. If empty, a new namespace will be created."
  type        = string
  default     = ""
}

locals {
  kubeconfig_path   = pathexpand("~/.kube/config")
  create_namespace  = var.namespace == ""
  generated_ns_name = format("stratus-red-team-privileged-name-%s", random_string.suffix.result)
  namespace         = local.create_namespace ? local.generated_ns_name : var.namespace
}

# Use ~/.kube/config as a configuration file if it exists (with current context).
# Fallback to using in-cluster configuration
# see https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs#authentication
provider "kubernetes" {
  config_path = fileexists(local.kubeconfig_path) ? local.kubeconfig_path : null
}

resource "random_string" "suffix" {
  length    = 8
  min_lower = 8
}

resource "kubernetes_namespace" "namespace" {
  count = local.create_namespace ? 1 : 0
  metadata {
    name   = local.generated_ns_name
    labels = { "datadoghq.com/stratus-red-team" : true }
  }
}

output "namespace" {
  value = local.namespace
}

output "display" {
  value = format("Namespace %s ready", local.namespace)
}
