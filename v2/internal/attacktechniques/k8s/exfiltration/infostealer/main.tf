terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.7.1"
    }
  }
}

variable "image" {
  description = "Container image to use for the pod."
  type        = string
  default     = "public.ecr.aws/docker/library/alpine:3.15.0"
}

variable "labels" {
  description = "JSON-encoded map of additional labels to apply to pods."
  type        = string
  default     = "{}"
}

variable "namespace" {
  description = "Kubernetes namespace to use. If empty, a new namespace will be created."
  type        = string
  default     = ""
}

variable "node_selector" {
  description = "JSON-encoded map of node selector labels."
  type        = string
  default     = "{}"
}

variable "tolerations" {
  description = "JSON-encoded list of tolerations for the pod."
  type        = string
  default     = "[]"
}

locals {
  kubeconfig_path = pathexpand("~/.kube/config")

  base_labels = {
    "datadoghq.com/stratus-red-team" : true
  }
  custom_labels = jsondecode(var.labels)
  labels        = merge(local.base_labels, local.custom_labels)

  create_namespace  = var.namespace == ""
  generated_ns_name = format("stratus-red-team-infostealer-%s", random_string.suffix.result)
  namespace         = local.create_namespace ? local.generated_ns_name : var.namespace

  node_selector   = jsondecode(var.node_selector)
  resource_prefix = "stratus-red-team-infostealer"
  tolerations     = jsondecode(var.tolerations)
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
    labels = local.base_labels
  }
}

resource "kubernetes_pod" "pod" {
  metadata {
    name      = format("%s-pod", local.resource_prefix)
    labels    = local.labels
    namespace = local.namespace
  }
  spec {
    node_selector = local.node_selector
    container {
      image   = var.image
      name    = "main-container"
      command = ["/bin/sh"]
      args    = ["-c", "while true; do sleep 3600; done"]
    }
    dynamic "toleration" {
      for_each = local.tolerations
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
