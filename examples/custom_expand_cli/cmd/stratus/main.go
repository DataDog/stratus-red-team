package main

import (
	_ "github.com/datadog/stratus-red-team/examples/custom_expand_cli/attacktechniques"

	"github.com/datadog/stratus-red-team/v2/cmd/stratus/cmd"
)

func main() {
	cmd.RootCmd.Execute()
}
