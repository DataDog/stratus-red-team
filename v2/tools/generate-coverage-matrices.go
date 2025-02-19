package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
)

func GenerateCoverageMatrices(index map[stratus.Platform]map[string][]*stratus.AttackTechnique, docsDirectory string) error {
	// Process each platform in the index
	for platform, tacticsMap := range index {
		// Initialize the HTML content
		htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<title>%s Coverage Matrix</title>
	<link rel="icon" type="image/png" href="logo.png">
	<style>
		body { font-family: Arial, sans-serif; margin: 20px;}
		table { width: 100%%; border-collapse: collapse; margin: 20px 0; font-size: 12px}
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; color: #7e56c2}
		th { background-color: #f4f4f4; font-weight: bold; font-size: 14px; color: #333; }
		tr:nth-child(even) { background-color: #f9f9f9; }
		tr:hover { background-color: #f1f1f1; }
		td:hover { background-color: #e9e9ff; color: #5a3ea8; cursor: pointer;}
		caption { font-size: 1.5em; margin-bottom: 10px; font-weight: bold; }
	</style>
</head>
<body>
	<h1>Stratus Red Team</h1>
	<table>
		<caption>Coverage Matrix for %s</caption>
`, platform, platform)

		// Extract unique tactics
		tacticsSet := make(map[string]struct{})
		for tactic := range tacticsMap {
			tacticsSet[tactic] = struct{}{}
		}
		tactics := make([]string, 0, len(tacticsSet))
		for tactic := range tacticsSet {
			tactics = append(tactics, tactic)
		}
		sort.Strings(tactics)

		// Add header row
		htmlContent += "<thead><tr>"
		for _, tactic := range tactics {
			htmlContent += fmt.Sprintf("<th>%s</th>", tactic)
		}
		htmlContent += "</tr></thead>\n<tbody>\n"

		rows := make([][]string, 0)
		maxRows := 0

		// Map tactic to techniques
		tacticToTechniques := make(map[string][]string)
		for _, tactic := range tactics {
			techniques := tacticsMap[tactic]
			for _, technique := range techniques {
				tacticToTechniques[tactic] = append(tacticToTechniques[tactic], technique.FriendlyName)
			}
			if len(tacticToTechniques[tactic]) > maxRows {
				maxRows = len(tacticToTechniques[tactic])
			}
		}

		// Fill rows with Stratus techniques for each ATT&CK tactic
		for i := 0; i < maxRows; i++ {
			row := make([]string, len(tactics))
			for j, tactic := range tactics {
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

		// Close table and HTML document
		htmlContent += `
		</tbody>
	</table>
</body>
</html>`
		filePath := filepath.Join(docsDirectory, fmt.Sprintf("%s.html", platform))
		if err := os.WriteFile(filePath, []byte(htmlContent), 0644); err != nil {
			return fmt.Errorf("failed to write HTML file for platform %s: %w", platform, err)
		}
		fmt.Printf("Generated coverage matrix for platform: %s\n", platform)
	}

	return nil
}