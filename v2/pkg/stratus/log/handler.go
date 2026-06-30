package log

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// LegacyHandler is an slog.Handler that reproduces the historical Stratus log
// format ("2006/01/02 15:04:05 message"), matching the standard library's log
// package with its default flags (Ldate | Ltime). It exists so that adopting
// slog does not change the CLI's on-screen output when no custom logger is set.
//
// Structured attributes are appended as " key=value" pairs after the message.
// The current codebase logs none, so output is byte-for-byte identical to the
// previous behaviour; the handling is kept correct for forward compatibility.
type LegacyHandler struct {
	// mutex is shared with handlers derived via WithAttrs/WithGroup so that
	// concurrent writes to the same writer stay serialised.
	mutex  *sync.Mutex
	writer io.Writer
	// level is the minimum level the handler emits. The standard library's log
	// package had no notion of levels, so the default is Info: everything that
	// was printed before still prints, while Debug becomes suppressible.
	level slog.Level
	// attributes is the pre-rendered " key=value" prefix accumulated through
	// WithAttrs. It is empty for a freshly constructed handler.
	attributes string
}

// NewLegacyHandler returns a handler that writes the historical Stratus log
// format to writer, emitting records at Info level and above.
func NewLegacyHandler(writer io.Writer) *LegacyHandler {
	return &LegacyHandler{mutex: &sync.Mutex{}, writer: writer, level: slog.LevelInfo}
}

// Enabled reports whether the handler handles records at the given level. The
// legacy format carried no level filtering beyond the Info floor set at
// construction.
func (h *LegacyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle renders record as a single line in the historical format. The context
// is intentionally unused: the legacy text format carries no contextual fields.
// Writes are serialised through the shared mutex so concurrent loggers and
// WithAttrs-derived handlers never interleave on the same writer.
func (h *LegacyHandler) Handle(_ context.Context, record slog.Record) error {
	timestamp := record.Time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	var builder strings.Builder
	// "2006/01/02 15:04:05 " is 20 bytes; reserve message + attributes + that
	// prefix up front to avoid reallocations while appending.
	builder.Grow(len(record.Message) + len(h.attributes) + 20)
	builder.WriteString(timestamp.Format("2006/01/02 15:04:05 "))
	builder.WriteString(record.Message)
	builder.WriteString(h.attributes)
	record.Attrs(func(attr slog.Attr) bool {
		appendAttr(&builder, attr)
		return true
	})
	builder.WriteByte('\n')

	h.mutex.Lock()
	defer h.mutex.Unlock()
	_, err := io.WriteString(h.writer, builder.String())
	return err
}

// WithAttrs returns a handler that prepends attrs (rendered once, here) to every
// subsequent record. The derived handler shares the receiver's mutex and writer
// so writes from both stay serialised against the same output.
func (h *LegacyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	var builder strings.Builder
	builder.WriteString(h.attributes)
	for i := range attrs {
		appendAttr(&builder, attrs[i])
	}
	return &LegacyHandler{
		mutex:      h.mutex,
		writer:     h.writer,
		level:      h.level,
		attributes: builder.String(),
	}
}

// WithGroup is a no-op: the legacy format does not represent groups. Group
// names are dropped while attributes continue to render flat.
func (h *LegacyHandler) WithGroup(string) slog.Handler {
	return h
}

// appendAttr renders a single attribute as " key=value" into builder, the flat
// form shared by Handle (per-record attrs) and WithAttrs (handler-level attrs).
func appendAttr(builder *strings.Builder, attr slog.Attr) {
	builder.WriteByte(' ')
	builder.WriteString(attr.Key)
	builder.WriteByte('=')
	builder.WriteString(attr.Value.String())
}
