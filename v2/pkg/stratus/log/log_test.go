package log

import (
	"bytes"
	"context"
	"encoding/json"
	stdlog "log"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// withRestoredLogger swaps the process-global logger for the duration of a test
// and restores it afterwards. Because it mutates package-global state, tests
// using it (directly or via captureJSON) must not call t.Parallel().
func withRestoredLogger(t *testing.T, logger *slog.Logger) {
	t.Helper()
	previous := current.Load()
	current.Store(logger)
	t.Cleanup(func() { current.Store(previous) })
}

// captureJSON installs a JSON logger writing into the returned buffer, so tests
// can assert on level and message without depending on wall-clock time.
func captureJSON(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	withRestoredLogger(t, slog.New(slog.NewJSONHandler(&buffer, nil)))
	return &buffer
}

func decode(t *testing.T, buffer *bytes.Buffer) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatalf("log output is not valid JSON (%q): %s", buffer.String(), err)
	}
	return record
}

// TestLegacyHandlerMatchesStdlibLog treats the standard library logger as the
// oracle: the LegacyHandler exists only to reproduce its default format, so we
// diff against the real thing rather than a transcribed format string.
func TestLegacyHandlerMatchesStdlibLog(t *testing.T) {
	const message = "Warming up aws.defense-evasion.cloudtrail-delete"

	var stdlibOutput, ourOutput bytes.Buffer
	stdlog.New(&stdlibOutput, "", stdlog.LstdFlags).Println(message)
	slog.New(NewLegacyHandler(&ourOutput)).Info(message)

	// stdlib logger formats time.Now() with no injectable clock, so we mask digits
	// in both outputs before comparing.
	maskDigits := func(line string) string {
		return strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return '0'
			}
			return r
		}, line)
	}

	if got, want := maskDigits(ourOutput.String()), maskDigits(stdlibOutput.String()); got != want {
		t.Fatalf("legacy output shape = %q, want stdlib shape %q", got, want)
	}
}

func TestPrintHelpersRouteThroughLoggerAtInfo(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		logCall func()
		wantMsg string
	}{
		// fmt.Sprint inserts a space only between operands that are not both
		// strings, so two strings concatenate.
		{"Print", func() { Print("access key ", "AKIA123") }, "access key AKIA123"},
		// fmt.Sprintln space-separates and appends a newline that must be trimmed.
		{"Println", func() { Println("Created access key", "AKIA123") }, "Created access key AKIA123"},
		{"Printf", func() { Printf("removed %d access keys", 2) }, "removed 2 access keys"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			buffer := captureJSON(t)
			testCase.logCall()
			record := decode(t, buffer)
			if level := record["level"]; level != "INFO" {
				t.Fatalf("%s level = %v, want INFO", testCase.name, level)
			}
			if msg := record["msg"]; msg != testCase.wantMsg {
				t.Fatalf("%s msg = %q, want %q", testCase.name, msg, testCase.wantMsg)
			}
		})
	}
}

func TestSetLoggerReplacesGlobal(t *testing.T) {
	withRestoredLogger(t, slog.New(slog.DiscardHandler))
	var buffer bytes.Buffer
	replacement := slog.New(slog.NewJSONHandler(&buffer, nil))

	SetLogger(replacement)

	if Logger() != replacement {
		t.Fatal("SetLogger did not install the provided logger")
	}
	Info("through replacement")
	if msg := decode(t, &buffer)["msg"]; msg != "through replacement" {
		t.Fatalf("log did not route through the replacement logger: msg = %q", msg)
	}
}

func TestSetLoggerIgnoresNil(t *testing.T) {
	sentinel := slog.New(slog.DiscardHandler)
	withRestoredLogger(t, sentinel)

	SetLogger(nil)

	if Logger() != sentinel {
		t.Fatal("SetLogger(nil) must not replace the active logger")
	}
}

func TestDisableSilencesLogging(t *testing.T) {
	withRestoredLogger(t, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))

	Disable()

	if Logger().Enabled(context.Background(), slog.LevelError) {
		t.Fatal("Disable must leave the logger disabled at every level")
	}
}

func TestLegacyHandlerEnabledRespectsInfoFloor(t *testing.T) {
	handler := NewLegacyHandler(&strings.Builder{})
	for _, testCase := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelDebug, false},
		{slog.LevelInfo, true},
		{slog.LevelWarn, true},
		{slog.LevelError, true},
	} {
		if got := handler.Enabled(context.Background(), testCase.level); got != testCase.want {
			t.Fatalf("Enabled(%v) = %v, want %v", testCase.level, got, testCase.want)
		}
	}
}

// TestLegacyHandlerSerialisesConcurrentWrites is the meaningful concurrency
// test: several handlers derived from the same NewLegacyHandler share one mutex
// and writer, and must serialise so no line is lost or interleaved. It is the
// shared-mutex contract that the atomic.Pointer in SetLogger does not cover.
// Run with -race to also catch unsynchronised writer access.
func TestLegacyHandlerSerialisesConcurrentWrites(t *testing.T) {
	var buffer bytes.Buffer
	base := NewLegacyHandler(&buffer)
	handlers := []slog.Handler{
		base,
		base.WithAttrs([]slog.Attr{slog.String("a", "1")}),
		base.WithAttrs([]slog.Attr{slog.String("b", "2")}),
	}

	const linesPerHandler = 200
	var waitGroup sync.WaitGroup
	for i := range handlers {
		logger := slog.New(handlers[i])
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for range linesPerHandler {
				logger.Info("line")
			}
		}()
	}
	waitGroup.Wait()

	want := len(handlers) * linesPerHandler
	if got := strings.Count(buffer.String(), "\n"); got != want {
		t.Fatalf("serialised line count = %d, want %d (lines lost or interleaved)", got, want)
	}
}

// TestConcurrentLogAndSet exercises the atomic swap under the race detector:
// readers via the shims must never observe a nil or torn logger pointer while a
// writer swaps the global.
func TestConcurrentLogAndSet(t *testing.T) {
	withRestoredLogger(t, slog.New(slog.DiscardHandler))

	var waitGroup sync.WaitGroup
	for range 8 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for range 100 {
				Println("concurrent")
			}
		}()
	}
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for range 100 {
			SetLogger(slog.New(slog.DiscardHandler))
		}
	}()
	waitGroup.Wait()
}
