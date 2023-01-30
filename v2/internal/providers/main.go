package providers

import (
	"fmt"
	"github.com/google/uuid"
)

const StratusUserAgentPrefix = "stratus-red-team"

func GetStratusUserAgentForUUID(uuid uuid.UUID) string {
	return fmt.Sprintf("%s_%s", StratusUserAgentPrefix, uuid.String())
}
