package main

import (
	"github.com/spf13/cobra"
)

var BuildVersion = ""

func buildVersionCmd() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "version",
		Short: "Display the current CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			println(BuildVersion)
		},
	}
	return statusCmd
}
