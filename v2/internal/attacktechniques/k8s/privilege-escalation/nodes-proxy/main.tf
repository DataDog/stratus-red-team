terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.13.0"
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
  generated_ns_name = format("stratus-red-team-np-name-%s", random_string.suffix.result)
  namespace         = local.create_namespace ? local.generated_ns_name : var.namespace
  resource_prefix   = "stratus-red-team-np"
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

resource "kubernetes_cluster_role" "clusterrole" {
  metadata {
    name = format("%s-clusterrole", local.resource_prefix)
  }

  rule {
    api_groups = [""]
    resources  = ["nodes/proxy"]
    verbs      = ["get", "create"]
  }
}

resource "kubernetes_service_account" "sa" {
  metadata {
    name      = format("%s-sa", local.resource_prefix)
    namespace = local.namespace
  }
}

resource "kubernetes_cluster_role_binding" "crb" {
  metadata {
    name = format("%s-crb", local.resource_prefix)
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.clusterrole.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.sa.metadata[0].name
    namespace = kubernetes_service_account.sa.metadata[0].namespace
  }
}

output "service_account_name" {
  value = kubernetes_service_account.sa.metadata[0].name
}

output "service_account_namespace" {
  value = local.namespace
}
output "display" {
  value = format(
    "K8s service account with node/proxy permission is ready: %s in namespace %s",
    kubernetes_service_account.sa.metadata[0].name,
    local.namespace
  )
}
