package cmd

import (
	"errors"
	"log"
	"os"
	"strings"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/jedib0t/go-pretty/v6/table"
)

func GetDisplayTable() table.Writer {
	t := table.NewWriter()
	t.SetStyle(table.StyleDefault)
	t.SetOutputMirror(os.Stdout)
	return t
}

func resolveTechniques(names []string) ([]*stratus.AttackTechnique, error) {
	var result []*stratus.AttackTechnique
	for i := range names {
		technique := stratus.GetRegistry().GetAttackTechniqueByName(names[i])
		if technique == nil {
			return nil, errors.New("unknown technique name " + names[i])
		}
		result = append(result, technique)
	}
	return result, nil
}

func handleErrorsChannel(errors <-chan error, jobsCount int) bool {
	hasError := false
	for i := 0; i < jobsCount; i++ {
		err := <-errors
		if err != nil {
			log.Println(err)
			hasError = true
		}
	}

	return hasError
}

// VerifyPlatformRequirements ensures that the user is properly authenticated against all platforms
// of a list of attack techniques
func VerifyPlatformRequirements(attackTechniques []*stratus.AttackTechnique) {
	platforms := map[stratus.Platform]bool{}
	for i := range attackTechniques {
		currentPlatform := attackTechniques[i].Platform
		if _, checked := platforms[currentPlatform]; !checked {
			log.Println("Checking your authentication against " + string(currentPlatform))
			err := stratus.EnsureAuthenticated(currentPlatform)
			if err != nil {
				log.Fatal(err.Error())
			}
			platforms[currentPlatform] = true
		}
	}
}

func getTechniquesCompletion(completionPrefix string) []string {
	attackTechniques := stratus.GetRegistry().GetAttackTechniques(&stratus.AttackTechniqueFilter{})
	var matchingTechniques []string
	for _, technique := range attackTechniques {
		if strings.HasPrefix(technique.ID, completionPrefix) {
			matchingTechniques = append(matchingTechniques, technique.ID)
		}
	}
	return matchingTechniques
}
