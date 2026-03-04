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

# Creating your own attack techniques and still using as a CLI

!!! important

    Don't hesitate to contact us to add your new attack techniques to the repository! We happily accept contributions and would be happy to add them to the Stratus registry.

If you build new attack techniques and still want to use Stratus Red Team as a CLI rather than as a dependency, you can import `RootCmd` along with your attack techniques and rebuild the CLI.

See the [custom CLI example repo](../../examples/custom_expand_cli/) for more details.
