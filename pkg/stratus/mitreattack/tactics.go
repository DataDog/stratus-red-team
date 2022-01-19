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
