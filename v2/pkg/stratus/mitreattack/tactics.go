package mitreattack

import (
	"errors"
	"strings"
)

type Tactic int

var tactics = []string{
	"Unknown",
	"Initial Access",
	"Execution",
	"Persistence",
	"Privilege Escalation",
	"Defense Evasion",
	"Credential Access",
	"Discovery",
	"Lateral Movement",
	"Collection",
	"Exfiltration",
}

const (
	UNSPECIFIED Tactic = iota
	InitialAccess
	Execution
	Persistence
	PrivilegeEscalation
	DefenseEvasion
	CredentialAccess
	Discovery
	LateralMovement
	Collection
	Exfiltration
)

func AttackTacticFromString(name string) (Tactic, error) {
	lowerName := strings.ToLower(name)
	for i := range tactics {
		if strings.ToLower(tactics[i]) == lowerName {
			return Tactic(i), nil
		}
	}
	return -1, errors.New("unknown MITRE ATT&CK tactic: " + name)
}

func AttackTacticToString(tactic Tactic) string {
	return tactics[tactic]
}

// MarshalYAML implements the Marshaler interface from "gopkg.in/yaml.v3".
// This method makes Tactic type to return a string rather than an int when marshalling to YAML.
func (t Tactic) MarshalYAML() (interface{}, error) {
	return tactics[t], nil
}
