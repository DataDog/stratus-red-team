package main

import (
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	stratusrunner "github.com/datadog/stratus-red-team/pkg/stratus/runner"
)

/*
	This example warms up, then detonates a specific Stratus Red Team attack technique once you press enter.
*/
func main() {
	ttp := stratus.GetRegistry().GetAttackTechniqueByName("aws.defense-evasion.stop-cloudtrail")
	fmt.Println(ttp)

	stratusRunner := stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)
	_, err := stratusRunner.WarmUp()
	defer stratusRunner.CleanUp()
	if err != nil {
		fmt.Println("Could not warm up TTP: " + err.Error())
		return
	}
	fmt.Println("TTP is warm! Press enter to detonate it")
	fmt.Scanln()
	err = stratusRunner.Detonate()
	if err != nil {
		fmt.Println("Could not detonate TTP: " + err.Error())
	}
}
