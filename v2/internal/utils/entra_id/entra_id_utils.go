package entra_id_utils

import (
	"os"
	"strings"
)

const DefaultFictitiousAttackerEmail = "stratusredteam@gmail.com"
const AttackerEmailEnvVarKey = "STRATUS_RED_TEAM_ATTACKER_EMAIL"

func GetAttackerPrincipal() string {
	if attackerEmail := os.Getenv(AttackerEmailEnvVarKey); attackerEmail != "" {
		return strings.ToLower(attackerEmail)
	} else {
		return DefaultFictitiousAttackerEmail
	}
}
