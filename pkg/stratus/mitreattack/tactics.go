package mitreattack

import "errors"

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
	for i := range tactics {
		if tactics[i] == name {
			return Tactic(i), nil
		}
	}
	return -1, errors.New("unknown MITRE ATT&CK tactic: " + name)
}

func AttackTacticToString(tactic Tactic) string {
	return tactics[tactic]
}
