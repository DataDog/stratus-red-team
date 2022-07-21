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
  namespace       = format("stratus-red-team-%s", random_string.suffix.result)
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
  metadata {
    name   = local.namespace
    labels = { "datadoghq.com/stratus-red-team" : true }
  }
}

output "namespace" {
  value = kubernetes_namespace.namespace.metadata[0].name
}

resource "kubernetes_cluster_role" "clusterrole" {
  metadata {
    name = "stratus-red-team-node-proxy-clusterrole"
  }

  rule {
    api_groups = [""]
    resources  = ["nodes/proxy"]
    verbs      = ["get", "create"]
  }
}

resource "kubernetes_service_account" "sa" {
  metadata {
    name      = "stratus-red-team-node-proxy-sa"
    namespace = kubernetes_namespace.namespace.metadata[0].name
  }
}

resource "kubernetes_cluster_role_binding" "crb" {
  metadata {
    name = "stratus-red-team-node-proxy-crb"
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
  kubernetes_namespace.namespace.metadata[0].name
  )
}