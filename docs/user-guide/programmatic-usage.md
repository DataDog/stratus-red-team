# Programmatic Usage

Stratus Red Team is mainly used from the CLI, but you can use it programmatically as well!

## Installing Stratus Red Team as a dependency

Run:

```
go get github.com/datadog/stratus-red-team
go mod tidy
```

For local development, use the following line in your `go.mod` instead:

```
replace github.com/datadog/stratus-red-team => ../stratus-red-team
```

... and run `go mod tidy && go get -d`

## Example usage

```go
package main

import (
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/pkg/stratus/runner"
)

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
```

You can then run the code using `go run main.go`

## Notes

When using Stratus Red Team programmatically, it will persist its state just like when using the CLI. 

So for instance, if you warm up a specific attack technique programmatically, running `stratus status` will show the technique is in `WARM` state.