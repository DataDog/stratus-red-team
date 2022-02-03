terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.6.0"
    }
  }
}

locals {
  kubeconfig = pathexpand("~/.kube/config")
}

provider "kubernetes" {
  config_path = local.kubeconfig
}

resource "kubernetes_namespace" "namespace" {
  metadata {
    name   = "stratus-red-team"
    labels = { "datadoghq.com/stratus-red-team" : true }
  }
}

output "kube_config" {
  value = local.kubeconfig
}

output "namespace" {
  value = kubernetes_namespace.namespace.metadata[0].name
}

output "display" {
  value = format("Namespace %s ready", kubernetes_namespace.namespace.metadata[0].name)
}
