package stratus

// Framework is an enum for different attack frameworks.
type Framework string

const (
	// ThreatTechniqueCatalogAWS is the Threat Technique Catalog for AWS
	ThreatTechniqueCatalogAWS Framework = "Threat Technique Catalog for AWS"
)

// TechniqueMapping represents a mapping to a specific technique in a framework.
type TechniqueMapping struct {
	// Name of the tactic, e.g. "Initial Access"
	Name string `yaml:"name"`
	// ID of the tactic, e.g. "TA0001"
	ID string `yaml:"id"`
	// URL to the tactic definition
	URL string `yaml:"url"`
}

// FrameworkMappings represents a mapping of an attack technique to a framework.
type FrameworkMappings struct {
	// Name of the framework
	Framework Framework `yaml:"framework"`
	// List of technique mappings
	Techniques []TechniqueMapping `yaml:"techniques"`
}
