package main

import (
	"os"

	"github.com/datadog/stratus-red-team/v2/cmd/stratus/cmd"
)

func main() {
	// Exit with a non-zero status when a command (or flag validation) fails,
	// so the CLI is usable in scripts and CI. Cobra already prints the error.
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
