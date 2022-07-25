package main

import (
	"errors"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/domain"
	"github.com/jedib0t/go-pretty/v6/table"
	"log"
	"os"
	"strings"
)

func GetDisplayTable() table.Writer {
	t := table.NewWriter()
	t.SetStyle(table.StyleDefault)
	t.SetOutputMirror(os.Stdout)
	return t
}

func resolveTechniques(names []string) ([]*domain.AttackTechnique, error) {
	var result []*domain.AttackTechnique
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
func VerifyPlatformRequirements(attackTechniques []*domain.AttackTechnique) {
	platforms := map[domain.Platform]bool{}
	for i := range attackTechniques {
		currentPlatform := attackTechniques[i].Platform
		if _, checked := platforms[currentPlatform]; !checked {
			log.Println("Checking your authentication against " + string(currentPlatform))
			if !IsAuthenticatedAgainstPlatform(currentPlatform) {
				log.Fatalf("You are not properly authenticated against " + string(currentPlatform))
			}
			platforms[currentPlatform] = true
		}
	}
}

func IsAuthenticatedAgainstPlatform(platform domain.Platform) bool {
	switch platform {
	case domain.AWS:
		return stratusRedTeam.Providers.GetAWSProvider().IsAuthenticatedAgainstAWS()
	case domain.Azure:
		return stratusRedTeam.Providers.GetAzureProvider().IsAuthenticatedAgainstAzure()
	case domain.Kubernetes:
		return stratusRedTeam.Providers.GetK8sProvider().IsAuthenticated()
	}
	return false
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
