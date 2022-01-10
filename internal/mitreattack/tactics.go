package mitreattack

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
