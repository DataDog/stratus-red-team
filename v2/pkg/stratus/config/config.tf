variable "config" {
  type = object({
    kubernetes = object({
      namespace = optional(string, "")
      pod = optional(object({
        image         = optional(string, "")
        labels        = optional(map(string), {})
        node_selector = optional(map(string), {})
        tolerations = optional(list(object({
          key      = string
          operator = string
          value    = string
          effect   = string
        })), [])
      }), { image = "", labels = {}, node_selector = {}, tolerations = [] })
    })
  })
  default = {
    kubernetes = {
      namespace = ""
      pod = {
        image         = ""
        labels        = {}
        node_selector = {}
        tolerations   = []
      }
    }
  }
}
