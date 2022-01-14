package main

import (
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"log"
)

func do_cleanup_cmd(techniques []*stratus.AttackTechnique) {
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], false, true) // TODO only for running
		log.Println("Cleaning up " + techniques[i].ID)
		err := runner.CleanUp()
		if err != nil {
			log.Println("Failed to clean up: " + err.Error())
			// continue cleaning up other techniques
		}
	}
	do_status_cmd(techniques)
}
