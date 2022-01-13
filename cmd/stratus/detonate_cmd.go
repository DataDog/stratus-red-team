package main

import (
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"log"
)

func do_detonate_cmd(techniques []*stratus.AttackTechnique, warmup bool, cleanup bool) {
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], warmup, cleanup)
		err := runner.Detonate()
		if err != nil {
			log.Fatal(err)
		}
	}
}
