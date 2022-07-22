# Programmatic Usage

Stratus Red Team is mainly used from the CLI, but you can use it programmatically as well! Use-cases include automation, and creating your own attack techniques.


!!! info

    When using Stratus Red Team programmatically, it will persist its state just like when using the CLI. 

    So for instance, if you warm up a specific attack technique programmatically, running `stratus status` will show the technique is in `WARM` state.

## Installing Stratus Red Team as a dependency

Run:

```
go get github.com/datadog/stratus-red-team/v2
go get -d
```

## Example usage

See https://github.com/DataDog/stratus-red-team/tree/main/examples

## Reference

https://pkg.go.dev/github.com/datadog/stratus-red-team/v2/pkg/stratus
