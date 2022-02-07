package main

import (
	"runtime"

	_ "github.com/datadog/stratus-red-team/internal/attacktechniques"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "stratus",
}

var (
	maxWorkerCount = runtime.GOMAXPROCS(0)
)

func init() {
	listCmd := buildListCmd()
	showCmd := buildShowCmd()
	warmupCmd := buildWarmupCmd()
	detonateCmd := buildDetonateCmd()
	revertCmd := buildRevertCmd()
	statusCmd := buildStatusCmd()
	cleanupCmd := buildCleanupCmd()
	versionCmd := buildVersionCmd()

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(warmupCmd)
	rootCmd.AddCommand(detonateCmd)
	rootCmd.AddCommand(revertCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(cleanupCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	rootCmd.Execute()
}
