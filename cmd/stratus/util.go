package main

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"os"
)

func GetDisplayTable() table.Writer {
	t := table.NewWriter()
	t.SetStyle(table.StyleDefault)
	t.SetOutputMirror(os.Stdout)
	return t
}
