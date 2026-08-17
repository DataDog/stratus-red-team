variable "correlation" {
  description = "Correlation metadata for this detonation, used to tag resources for signal matching."
  type = object({
    id = optional(string, "")
    # Short, name-safe form of the id. Embed it in resource names so that concurrent
    # executions of the technique do not collide on names with tight length limits.
    short = optional(string, "")
  })
  default = {
    id    = ""
    short = ""
  }
}
