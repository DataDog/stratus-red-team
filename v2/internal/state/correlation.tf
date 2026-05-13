variable "correlation" {
  description = "Correlation metadata for this detonation, used to tag resources for signal matching."
  type = object({
    id = optional(string, "")
  })
  default = {
    id = ""
  }
}
