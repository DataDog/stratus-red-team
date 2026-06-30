package loader

import (
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques" // Required for programmatic usage
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
)

func init() {
	// Silence Stratus by default for programmatic usage.
	// Users can opt back in via log.SetLogger.
	log.Disable()
}
