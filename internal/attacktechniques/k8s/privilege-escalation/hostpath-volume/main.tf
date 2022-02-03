terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.7.1"
    }
  }
}

variable "kubeconfig" {
  type        = string
  description = "Path to KubeConfig"
  default     = "~/.kube/config"
}

# Sourcing kubernetes credentials
# 1. kubeconfig terraform variable
# 2. ~/.kube/config
# 3. Kubernetes in-cluster config
provider "kubernetes" {
  config_path = fileexists(pathexpand(var.kubeconfig)) ? pathexpand(var.kubeconfig) : null
}

resource "kubernetes_namespace" "namespace" {
  metadata {
    name   = "stratus-red-team"
    labels = { "datadoghq.com/stratus-red-team" : true }
  }
}

output "namespace" {
  value = kubernetes_namespace.namespace.metadata[0].name
}

output "display" {
  value = format("Namespace %s ready", kubernetes_namespace.namespace.metadata[0].name)
}
