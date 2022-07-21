package loader

import (
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques" // Required for programmatic usage
	"io"
	"log"
)

func init() {
	// Disable logging for programmatic usage
	log.SetOutput(io.Discard)
}
