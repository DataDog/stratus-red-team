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
  namespace = format("stratus-red-team-%s", random_string.suffix.result)
  labels = {
    "datadoghq.com/stratus-red-team": true
  }
  pod_name = "stratus-red-team-sample-pod"
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
    labels = local.labels
  }
}

resource "kubernetes_service_account" "serviceaccount" {
  metadata {
    name = "stratus-red-team-sa"
    labels = local.labels
    namespace = kubernetes_namespace.namespace.metadata[0].name
  }
}

resource "kubernetes_pod" "pod" {
  metadata {
    name = local.pod_name
    labels = local.labels
    namespace = local.namespace
  }
  spec {
    service_account_name = kubernetes_service_account.serviceaccount.metadata[0].name
    container {
      image = "public.ecr.aws/docker/library/alpine:3.15.0"
      name = "main-container"
      command = ["/bin/sh"]
      args = ["-c", "while true; do sleep 3600; done"]
    }
  }
}

output "namespace" {
  value = kubernetes_namespace.namespace.metadata[0].name
}

output "pod_name" {
  value = kubernetes_pod.pod.metadata[0].name
}

output "display" {
  value = format("Pod %s in namespace %s ready", kubernetes_pod.pod.metadata[0].name, kubernetes_namespace.namespace.metadata[0].name)
}
