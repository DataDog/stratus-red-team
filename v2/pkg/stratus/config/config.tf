variable "config" {
  type = object({
    aws = optional(object({
      prefix = optional(string, "")
      tags   = optional(map(string), {})
    }), { prefix = "", tags = {} })
    kubernetes = optional(object({
      namespace = optional(string, "")
      pod = optional(object({
        image            = optional(string, "")
        labels           = optional(map(string), {})
        annotations      = optional(map(string), {})
        node_selector    = optional(map(string), {})
        security_context = optional(any, {})
        tolerations = optional(list(object({
          key      = string
          operator = string
          value    = string
          effect   = string
        })), [])
      }), { image = "", labels = {}, annotations = {}, node_selector = {}, security_context = {}, tolerations = [] })
    }), { namespace = "", pod = { image = "", labels = {}, annotations = {}, node_selector = {}, security_context = {}, tolerations = [] } })
  })
  default = {
    aws = {
      prefix = ""
      tags   = {}
    }
    kubernetes = {
      namespace = ""
      pod = {
        image            = ""
        labels           = {}
        annotations      = {}
        node_selector    = {}
        security_context = {}
        tolerations      = []
      }
    }
  }
}
