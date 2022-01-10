package mitreattack

import "errors"

type Tactic string

const (
	InitialAccess       Tactic = "initial-access"
	Execution                  = "execution"
	Persistence                = "persistence"
	PrivilegeEscalation        = "privilege-escalation"
	DefenseEvasion             = "defense-evasion"
	CredentialAccess           = "credential-access"
	Discovery                  = "discovery"
	LateralMovement            = "lateral-movement"
	Collection                 = "collection"
	Exfiltration               = "exfiltration"
)

func AttackTacticFromString(name string) (Tactic, error) {
	switch name {
	case "initial-access":
		return InitialAccess, nil
	case "execution":
		return Execution, nil
	case "persistence":
		return Persistence, nil
	case "privilege-escalation":
		return PrivilegeEscalation, nil
	case "defense-evasion":
		return DefenseEvasion, nil
	case "credential-access":
		return CredentialAccess, nil
	case "discovery":
		return Discovery, nil
	case "lateral-movement":
		return LateralMovement, nil
	case "collection":
		return Collection, nil
	case "exfiltration":
		return Exfiltration, nil
	default:
		return "", errors.New("unknown MITRE ATT&CK tactic: " + name)
	}
}
