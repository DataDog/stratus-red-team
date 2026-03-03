package stratus

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

type AttackTechnique struct {
	// Short identifier, e.g. aws.persistence.create-iam-user
	ID string `yaml:"id"`

	// Friendly-looking short name
	FriendlyName string `yaml:"name"`

	// Full description (multi-line)
	Description string `yaml:"-"`

	// Pointer and leads for detection opportunities (multi-line)
	Detection string `yaml:"-"`

	// Indicates if the technique is expected to be slow to warm-up or detonate
	IsSlow bool `yaml:"isSlow"`

	// MITRE ATT&CK Tactics to which this technique maps
	// see https://attack.mitre.org/techniques/enterprise/
	MitreAttackTactics []mitreattack.Tactic `yaml:"mitreAttackTactics"`

	// Mappings to other frameworks
	FrameworkMappings []FrameworkMappings `yaml:"frameworkmappings,omitempty"`

	// The platform of the technique, e.g. AWS
	Platform Platform `yaml:"platform"`

	// Terraform code to apply to create the necessary prerequisites for the technique to be detonated
	PrerequisitesTerraformCode []byte `yaml:"-"`

	// TerraformOverrideConfig represents the variables defined in the `PrerequisitesTerraformCode`
	// that can be overridden from the config file.
	// Overrides are the dotted paths to the values in the config file. In the terraform code, these
	// variables must be defined as a "config" object whose structure is the overrides dot-separated paths.
	//
	// See the "Configuration File" section of the Getting Started guide for more details.
	//
	// Example:
	//   // Terraform code
	//   variable "config" {
	//     type = object({
	//       kubernetes = object({
	//         namespace = optional(string, "")
	//       })
	//     })
	//     default = {
	//       kubernetes = {
	//         namespace = ""
	//       }
	//     }
	//   }
	//   // Config file
	//   kubernetes:
	//     default:
	//       namespace: "my-namespace"
	//       pod:
	//         image: "my-image"
	//   // Override array
	//   overrides := []string{"kubernetes.namespace", "kubernetes.pod.image"}
	TerraformOverrideConfig []string `yaml:"-"`

	// Detonation function
	// Parameters are the Terraform outputs
	Detonate func(params map[string]string, providerFactory CloudProviders) error `yaml:"-"`

	// Indicates if the detonation function is idempotent, i.e. if it can be run multiple times without reverting it
	IsIdempotent bool `yaml:"isIdempotent"`

	// Reversion function, to revert the side effects of a detonation
	Revert func(params map[string]string, providerFactory CloudProviders) error `yaml:"-"`
}

func (m AttackTechnique) String() string {
	return m.ID
}
