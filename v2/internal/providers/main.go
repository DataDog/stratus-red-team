package providers

import (
	"fmt"
	"github.com/google/uuid"
)

const StratusUserAgent = "stratus-red-team"

var UniqueExecutionId = uuid.New()

func GetStratusUserAgent() string {
	return fmt.Sprintf("%s_%s", StratusUserAgent, UniqueExecutionId)
}
