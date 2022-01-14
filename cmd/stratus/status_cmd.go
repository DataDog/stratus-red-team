package main

import (
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/jedib0t/go-pretty/v6/table"
)

func do_status_cmd(techniques []*stratus.AttackTechnique) {
	t := GetDisplayTable()
	t.AppendHeader(table.Row{"ID", "Name", "Status"})
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], true, true)
		t.AppendRow(table.Row{techniques[i].ID, techniques[i].FriendlyName, runner.GetState()})
	}
	t.Render()
}
