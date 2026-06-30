# Custom logger example

Shows how to take control of Stratus Red Team's logging when using it as a Go
library, instead of letting it write plain text to stdout.

By default, importing `pkg/stratus/loader` silences Stratus (the CLI keeps its
historical plain-text format). To route Stratus logs through your own logger,
call `log.SetLogger` once at startup with any `*slog.Logger`:

```go
import (
    "log/slog"

    stratuslog "github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
    "go.uber.org/zap"
    "go.uber.org/zap/exp/zapslog"
)

func init() {
    zapLogger, _ := zap.NewProduction()
    handler := zapslog.NewHandler(zapLogger.Core(), zapslog.WithCaller(false))
    stratuslog.SetLogger(slog.New(handler))
}
```

From then on, both the runner's own log lines and every attack technique's log
lines are emitted through your logger as structured JSON. Stratus itself only
depends on the standard library's `log/slog`; the
[`zapslog`](https://pkg.go.dev/go.uber.org/zap/exp/zapslog) bridge keeps the
zap dependency on the embedding side.

The logger is process-global and is meant to be set once during
initialisation. Per-detonation fields (for example a correlation ID on each
technique's log lines) are not yet supported -- the logger carries only the
static fields configured at startup.

## Running

```bash
go run .
```

Requires AWS credentials, as it warms up and detonates
`aws.defense-evasion.cloudtrail-stop`.
