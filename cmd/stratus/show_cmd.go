package main

import (
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
)

func do_show_cmd(techniques []*stratus.AttackTechnique) {
	for i := range techniques {
		fmt.Println(techniques[i].Description)
	}
}
