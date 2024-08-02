package useragent

import (
	"fmt"
	"github.com/google/uuid"
)

// Has to be in a separate package to avoid circular dependencies

const StratusUserAgentPrefix = "stratus-red-team"

func GetStratusUserAgentForUUID(uuid uuid.UUID) string {
	return fmt.Sprintf("%s_%s", StratusUserAgentPrefix, uuid.String())
}
