terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.13.0"
    }
  }
}

locals {
  kubeconfig_path = pathexpand("~/.kube/config")

  base_labels = {
    "datadoghq.com/stratus-red-team" : true
    "datadoghq.com/stratus-red-team-correlation-id" : var.correlation.id
    "datadoghq.com/stratus-red-team-stage" : "warmup"
  }
  custom_labels = var.config.kubernetes.pod.labels
  labels        = merge(local.base_labels, local.custom_labels)

  create_namespace  = var.config.kubernetes.namespace == ""
  generated_ns_name = format("stratus-red-team-%s", random_string.suffix.result)
  namespace         = local.create_namespace ? local.generated_ns_name : var.config.kubernetes.namespace

  image = var.config.kubernetes.pod.image != "" ? var.config.kubernetes.pod.image : "public.ecr.aws/docker/library/alpine:3.15.0"

  resource_prefix = "stratus-red-team-ssat" # stratus red team steal service account token
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
    labels = local.labels
  }
}

resource "kubernetes_service_account" "serviceaccount" {
  metadata {
    name      = format("%s-sa", local.resource_prefix)
    labels    = local.labels
    namespace = local.namespace
  }
}

resource "kubernetes_pod" "pod" {
  metadata {
    name        = format("%s-pod", local.resource_prefix)
    labels      = local.labels
    annotations = var.config.kubernetes.pod.annotations
    namespace   = local.namespace
  }
  spec {
    service_account_name = kubernetes_service_account.serviceaccount.metadata[0].name
    node_selector        = var.config.kubernetes.pod.node_selector
    container {
      image   = local.image
      name    = "main-container"
      command = ["/bin/sh"]
      args    = ["-c", "while true; do sleep 3600; done"]
    }
    dynamic "toleration" {
      for_each = var.config.kubernetes.pod.tolerations
      content {
        key      = toleration.value.key
        operator = toleration.value.operator
        value    = toleration.value.value
        effect   = toleration.value.effect
      }
    }
  }
}

output "namespace" {
  value = local.namespace
}

output "pod_name" {
  value = kubernetes_pod.pod.metadata[0].name
}

output "display" {
  value = format("Pod %s in namespace %s ready", kubernetes_pod.pod.metadata[0].name, local.namespace)
}
