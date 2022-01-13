package main

import (
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"log"
)

func do_warmup_cmd(techniques []*stratus.AttackTechnique, warmup bool) {
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], warmup, true)
		_, err := runner.WarmUp()
		if err != nil {
			log.Fatal(err)
		}
	}
}
