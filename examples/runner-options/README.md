# Example: using runner options to inject custom dependencies

This example shows how to wrap the default `TerraformManager` with a logging decorator, then inject it into the runner via `WithTerraformManager`.

The same pattern works for any runner dependency: `WithStateManager`, `WithProviderFactory`, `WithConfig`, `WithCorrelationID`.

```
go get github.com/datadog/stratus-red-team
go get -d
go run main.go
```
