package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
)

// Define MITRE ATT&CK tactic order from MITRE website
var mitreTacticOrder = []string{
	"Reconnaissance",
	"Resource Development",
	"Initial Access",
	"Execution",
	"Persistence",
	"Privilege Escalation",
	"Defense Evasion",
	"Credential Access",
	"Discovery",
	"Lateral Movement",
	"Collection",
	"Command and Control",
	"Exfiltration",
	"Impact",
}

// GenerateCoverageMatrics generates a single static .md file containing MITRE ATT&CK coverage tables split by platform
func GenerateCoverageMatrices(index map[stratus.Platform]map[string][]*stratus.AttackTechnique, docsDirectory string) error {
	outputFilePath := filepath.Join(docsDirectory, "attack-techniques", "mitre-attack-coverage-matrices.md")

	if err := os.MkdirAll(filepath.Dir(outputFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create docs directory: %w", err)
	}

	if _, err := os.Stat(outputFilePath); err == nil {
		if err := os.Remove(outputFilePath); err != nil {
			return fmt.Errorf("failed to delete existing file: %w", err)
		}
	}

	file, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	htmlContent := `
<style>
	table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 16px; }
	th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
	.md-sidebar.md-sidebar--secondary { display: none; }
	.md-content { min-width: 100%; }
</style>

# MITRE ATT&CK Coverage by Platform

This provides coverage matrices of MITRE ATT&CK tactics and techniques currently covered by Stratus Red Team for different cloud platforms.
`

	// Loop through each platform and generate tables
	for platform, tacticsMap := range index {
		htmlContent += fmt.Sprintf("<h2 style=\"text-transform: uppercase;\">%s</h2>\n<table>\n", platform)

		// Sort tactics based on MITRE ATT&CK order
		sortedTactics := []string{}
		tacticSet := make(map[string]bool)

		// Collect tactics present for specific platform
		for tactic := range tacticsMap {
			tacticSet[tactic] = true
		}

		// Append tactics in the correct order
		for _, tactic := range mitreTacticOrder {
			if tacticSet[tactic] {
				sortedTactics = append(sortedTactics, tactic)
			}
		}

		// Add table header with sorted tactics
		htmlContent += "<thead><tr>"
		for _, tactic := range sortedTactics {
			htmlContent += fmt.Sprintf("<th>%s</th>", tactic)
		}
		htmlContent += "</tr></thead>\n<tbody>\n"

		// Create a list of rows
		rows := make([][]string, 0)
		maxRows := 0

		// Map each tactic to its respective techniques (column by column)
		tacticToTechniques := make(map[string][]string)
		for _, tactic := range sortedTactics {
			techniques := tacticsMap[tactic]
			for _, technique := range techniques {
				platform, _ := technique.Platform.FormatName()
				cellText := fmt.Sprintf("<a href=\"%s\">%s</a>", fmt.Sprintf("../%s/%s", platform, technique.ID), technique.FriendlyName)
				tacticToTechniques[tactic] = append(tacticToTechniques[tactic], cellText)
			}
			if len(tacticToTechniques[tactic]) > maxRows {
				maxRows = len(tacticToTechniques[tactic])
			}
		}

		// Fill rows with techniques for each tactic
		for i := 0; i < maxRows; i++ {
			row := make([]string, len(sortedTactics))
			for j, tactic := range sortedTactics {
				if i < len(tacticToTechniques[tactic]) {
					row[j] = tacticToTechniques[tactic][i]
				} else {
					row[j] = ""
				}
			}
			rows = append(rows, row)
		}

		// Add rows to the HTML table
		for _, row := range rows {
			htmlContent += "<tr>"
			for _, cell := range row {
				if cell != "" {
					htmlContent += fmt.Sprintf("<td>%s</td>", cell)
				} else {
					htmlContent += "<td></td>"
				}
			}
			htmlContent += "</tr>\n"
		}

		htmlContent += "</tbody>\n</table>\n"
	}

	htmlContent += `
</body>
</html>`

	if _, err := file.WriteString(htmlContent); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}
