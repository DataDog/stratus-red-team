package main

import (
	"github.com/datadog/stratus-red-team/internal/runner"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/jedib0t/go-pretty/v6/table"
	"os"
)

func do_status_cmd(techniques []*stratus.AttackTechnique) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Technique", "Status"})
	for i := range techniques {
		runner := runner.NewRunner(techniques[i], true, true)
		t.AppendRow(table.Row{techniques[i].Name, runner.GetState()})
	}
	t.Render()
}
