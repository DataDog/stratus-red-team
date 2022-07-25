package providers

import (
	"fmt"
)

const StratusUserAgent = "stratus-red-team"

func GetStratusUserAgent(uniqueExecutionId string) string {
	return fmt.Sprintf("%s_%s", StratusUserAgent, uniqueExecutionId)
}
