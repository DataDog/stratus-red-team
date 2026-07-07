package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratuslog "github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

// init routes all Stratus logs through zap, once, at startup. Importing the
// loader package silences Stratus by default; SetLogger opts back in.
func init() {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Errorf("unable to build zap logger: %w", err))
	}

	// zapslog bridges a zap core to an slog.Handler, keeping the zap
	// dependency on the embedder's side. Caller reporting is off because the
	// stdlib-compatible log helpers would report the Stratus log package as
	// the caller (see README).
	handler := zapslog.NewHandler(zapLogger.Core(), zapslog.WithCaller(false))
	stratuslog.SetLogger(slog.New(handler))
}

func main() {
	ttp := stratus.GetRegistry().GetAttackTechniqueByName("aws.defense-evasion.cloudtrail-stop")
	runner := stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)

	_, err := runner.WarmUp()
	defer func() {
		if cleanupErr := runner.CleanUp(); cleanupErr != nil {
			stratuslog.Error("could not clean up TTP", "error", cleanupErr)
		}
	}()
	if err != nil {
		stratuslog.Error("could not warm up TTP", "error", err)
		return
	}

	// Require an actual line of input before detonating real cloud resources;
	// at EOF (non-interactive stdin) Scan returns false and we abort.
	fmt.Println("TTP is warm! Press enter to detonate it")
	confirmation := bufio.NewScanner(os.Stdin)
	if !confirmation.Scan() {
		stratuslog.Warn("no confirmation received, aborting detonation")
		return
	}

	if err := runner.Detonate(); err != nil {
		stratuslog.Error("could not detonate TTP", "error", err)
	}
}
