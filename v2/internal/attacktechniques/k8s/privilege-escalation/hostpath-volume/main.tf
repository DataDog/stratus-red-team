terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.7.1"
    }
  }
}

locals {
  kubeconfig_path = pathexpand("~/.kube/config")
  namespace       = format("stratus-red-team-hpns-%s", random_string.suffix.result)
}

# Use ~/.kube/config as a configuration file if it exists (with current context).
# Fallback to using in-cluster configuration
# see https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs#authentication
provider "kubernetes" {
  config_path = fileexists(local.kubeconfig_path) ? local.kubeconfig_path : null
}

resource "random_string" "suffix" {
  length    = 4
  min_lower = 4
}

resource "kubernetes_namespace" "namespace" {
  metadata {
    name   = local.namespace
    labels = { "datadoghq.com/stratus-red-team" : true }
  }
}

output "namespace" {
  value = kubernetes_namespace.namespace.metadata[0].name
}

output "display" {
  value = format("Namespace %s ready", kubernetes_namespace.namespace.metadata[0].name)
}
