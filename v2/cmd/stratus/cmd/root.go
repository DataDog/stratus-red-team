package cmd

import (
	"log"
	"os"

	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use: "stratus",
}

func init() {
	setupLogging()

	listCmd := buildListCmd()
	showCmd := buildShowCmd()
	warmupCmd := buildWarmupCmd()
	detonateCmd := buildDetonateCmd()
	revertCmd := buildRevertCmd()
	statusCmd := buildStatusCmd()
	cleanupCmd := buildCleanupCmd()
	versionCmd := buildVersionCmd()

	RootCmd.AddCommand(listCmd)
	RootCmd.AddCommand(showCmd)
	RootCmd.AddCommand(warmupCmd)
	RootCmd.AddCommand(detonateCmd)
	RootCmd.AddCommand(revertCmd)
	RootCmd.AddCommand(statusCmd)
	RootCmd.AddCommand(cleanupCmd)
	RootCmd.AddCommand(versionCmd)
}

func setupLogging() {
	log.SetOutput(os.Stdout)
}
