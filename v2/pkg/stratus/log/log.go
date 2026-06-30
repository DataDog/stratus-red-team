// Package log is the single logging facility used across Stratus Red Team.
//
// It wraps the standard library's log/slog behind a process-global logger so
// that both the CLI and embedders can control where Stratus output goes and in
// which format. The standard-library-compatible helpers (Print, Println,
// Printf, Fatal, Fatalf) keep the rest of the codebase logging without
// ceremony; the slog-native helpers (Info, Warn, Error, Debug, With) and the
// SetLogger entrypoint let embedders route everything through their own
// *slog.Logger -- for example a zap-backed handler built with
// go.uber.org/zap/exp/zapslog.
//
// The logger is a single process-global swapped atomically. It is meant to be
// configured once, early, during program initialisation: concurrent runners
// share it and cannot each carry their own request-scoped fields. Threading a
// per-runner logger through detonation is intentionally out of scope here.
package log

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// current holds the active logger. It is read on every log call and swapped
// atomically by SetLogger, so concurrent callers never observe a torn pointer.
var current atomic.Pointer[slog.Logger]

func init() {
	// Default to the historical stdout format so behaviour is unchanged when
	// nothing configures logging. Logging policy is then resolved by init order:
	// importing the loader package silences this (loader/main.go calls Disable),
	// and the CLI re-installs it explicitly (cmd/.../root.go setupLogging) so it
	// is unaffected if it transitively imports the loader. Keep these three in
	// sync when changing the default.
	current.Store(slog.New(NewLegacyHandler(os.Stdout)))
}

// SetLogger replaces the process-global logger. It is safe to call concurrently
// but is intended to be called once, early, during program initialisation. A
// nil logger is ignored to avoid leaving the package without a usable logger.
func SetLogger(logger *slog.Logger) {
	if logger == nil {
		return
	}
	current.Store(logger)
}

// Logger returns the active logger. It is never nil.
//
// The result is a point-in-time snapshot: a caller that holds onto it will not
// observe a subsequent SetLogger. Code that must always log through the current
// logger should call the package-level helpers (which re-read the global on
// every call) rather than caching this value.
func Logger() *slog.Logger {
	return current.Load()
}

// Disable silences all Stratus logging. It is used for programmatic usage,
// where the embedder is expected to opt back in via SetLogger.
func Disable() {
	current.Store(slog.New(slog.DiscardHandler))
}

// emit writes msg at info level after trimming a single trailing newline:
// fmt.Sprintln always appends one and a Printf format may include one, but slog
// records carry no trailing newline (the handler appends it).
func emit(msg string) {
	current.Load().Info(strings.TrimSuffix(msg, "\n"))
}

// Print logs its operands at info level using fmt.Sprint formatting.
func Print(v ...any) {
	emit(fmt.Sprint(v...))
}

// Println logs its operands at info level using fmt.Sprintln formatting.
func Println(v ...any) {
	emit(fmt.Sprintln(v...))
}

// Printf logs a formatted message at info level.
func Printf(format string, v ...any) {
	emit(fmt.Sprintf(format, v...))
}

// fatalMessage logs msg at error level. It is split out from Fatal/Fatalf so
// the formatting half can be tested without the os.Exit that follows it.
func fatalMessage(msg string) {
	current.Load().Error(strings.TrimSuffix(msg, "\n"))
}

// Fatal logs its operands at error level and then exits with status 1,
// mirroring the standard library's log.Fatal.
func Fatal(v ...any) {
	fatalMessage(fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf logs a formatted message at error level and then exits with status 1,
// mirroring the standard library's log.Fatalf.
func Fatalf(format string, v ...any) {
	fatalMessage(fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Info logs a structured message at info level.
func Info(msg string, args ...any) {
	current.Load().Info(msg, args...)
}

// Warn logs a structured message at warn level.
func Warn(msg string, args ...any) {
	current.Load().Warn(msg, args...)
}

// Error logs a structured message at error level.
func Error(msg string, args ...any) {
	current.Load().Error(msg, args...)
}

// Debug logs a structured message at debug level.
func Debug(msg string, args ...any) {
	current.Load().Debug(msg, args...)
}

// With returns a logger derived from the active logger with the given
// attributes attached. It does not modify the process-global logger.
func With(args ...any) *slog.Logger {
	return current.Load().With(args...)
}
