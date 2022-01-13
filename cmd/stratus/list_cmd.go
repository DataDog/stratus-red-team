package main

import (
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

func do_list_cmd(mitreAttackTactic string, platform string) {
	filter := stratus.AttackTechniqueFilter{}
	if platform != "" {
		platform, err := stratus.PlatformFromString(platform)
		if err != nil {
			log.Fatal(err)
		}
		filter.Platform = platform
	}
	if mitreAttackTactic != "" {
		tactic, err := mitreattack.AttackTacticFromString(mitreAttackTactic)
		if err != nil {
			log.Fatal(err)
		}
		filter.Tactic = tactic
	}
	techniques := stratus.GetRegistry().GetAttackTechniques(&filter)
	for i := range techniques {
		fmt.Println(techniques[i])
	}
}
