package loader

import (
	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques" // Required for programmatic usage
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
)

func init() {
	// Silence Stratus by default for programmatic usage; embedders opt back in
	// via log.SetLogger. This preserves the long-standing contract that merely
	// importing the loader (to register attack techniques) produces no log
	// output, so it stays in init() rather than becoming a separate call the
	// embedder must remember.
	log.Disable()
}
