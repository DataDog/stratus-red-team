# Example: Extending the `stratus` CLI with custom attack techniques

> [!IMPORTANT]  
> Don't hesitate to contact us to add your new attack techniques to the repository! We happily accept
> contributions and would be happy to add them to the Stratus registry.

If you build new attack techniques and still want to use Stratus Red Team as a CLI rather than just
detonating custom attacks programmatically (see the [custom](../custom/) example for that),
you can import `RootCmd` along with your attack techniques and rebuild the CLI.

## How it works

The custom CLI is built by:

1. Importing `github.com/datadog/stratus-red-team/v2/cmd/stratus/cmd` which exposes `RootCmd`
2. Importing your custom attack techniques package (which registers techniques in its `init()` functions)
3. Calling `cmd.RootCmd.Execute()` in your `main()` function

See [cmd/stratus/main.go](cmd/stratus/main.go) for the entry point.

## Project structure

```
custom_expand_cli/
├── cmd/stratus/
│   └── main.go                    # Entry point that imports RootCmd and custom techniques
├── attacktechniques/
│   └── aws/execution/
│       └── custom-iam-attack/
│           ├── main.go            # Attack technique implementation
│           └── main.tf            # Terraform prerequisites
├── go.mod
├── Makefile
└── README.md
```

## Building and running

```bash
# Build the custom CLI
make build

# Run the CLI
./stratus list
./stratus warmup my-sample-attack-technique
./stratus detonate my-sample-attack-technique
./stratus cleanup my-sample-attack-technique
```
