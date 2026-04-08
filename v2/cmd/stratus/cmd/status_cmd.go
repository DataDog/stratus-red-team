package cmd

import (
	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func buildStatusCmd() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Display the status of TTPs.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil // no technique specified == all techniques
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				techniques, _ := resolveTechniques(args)
				doStatusCmd(techniques)
			} else {
				doStatusCmd(stratus.GetRegistry().ListAttackTechniques())
			}
		},
	}
	return statusCmd
}

func doStatusCmd(techniques []*stratus.AttackTechnique) {
	t := GetDisplayTable()
	t.AppendHeader(table.Row{"ID", "Name", "Status"})
	for i := range techniques {
		stateManager := resolveStateManager(techniques[i])
		techniqueState := stateManager.GetTechniqueState()
		if techniqueState == "" {
			techniqueState = stratus.AttackTechniqueStatusCold
		}
		t.AppendRow(table.Row{techniques[i].ID, techniques[i].FriendlyName, colorState(techniqueState)})
	}
	t.Render()
}

// resolveStateManager returns the appropriate StateManager based on whether S3 remote state is configured
func resolveStateManager(technique *stratus.AttackTechnique) state.StateManager {
	s3Cfg := resolveS3BackendConfig()
	if s3Cfg != nil {
		return state.NewS3StateManager(technique, *s3Cfg)
	}
	return state.NewFileSystemStateManager(technique)
}

func colorState(state stratus.AttackTechniqueState) string {
	stateString := string(state)
	switch state {
	case stratus.AttackTechniqueStatusCold:
		return color.CyanString(stateString)
	case stratus.AttackTechniqueStatusWarm:
		return color.YellowString(stateString)
	case stratus.AttackTechniqueStatusDetonated:
		return color.MagentaString(stateString)
	default:
		return stateString
	}
}
