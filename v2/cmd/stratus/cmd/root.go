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

	RootCmd.PersistentFlags().StringVar(&flagStateBucket, "state-bucket", "", "(optional) S3 bucket for remote state storage")
	RootCmd.PersistentFlags().StringVar(&flagStateBucketRegion, "state-bucket-region", "", "(optional) AWS region of the S3 state bucket")

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
