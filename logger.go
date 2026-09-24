package supabase

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan

	levelDebug = "DEBUG"
	levelInfo  = "INFO"
	levelWarn  = "WARN"
	levelError = "ERROR"
	levelFatal = "FATAL"

	Tag = "tag"
)

var (
	formatLevel = map[string]string{
		"debug": colorize(levelDebug, colorMagenta),
		"info":  colorize(levelInfo, colorCyan),
		"warn":  colorize(levelWarn, colorYellow),
		"error": colorize(levelError, colorRed),
		"fatal": colorize(levelFatal, colorGreen),
	}
	// logger is the package-wide logger. It starts disabled so that
	// components constructed directly (NewAuth, NewPostgres, NewStorage)
	// without New never hit a nil logger; New swaps it according to
	// Config.Debug. The swap is atomic because New may run concurrently with
	// in-flight requests that log.
	logger = newLoggerHolder(buildLogger(false))
)

// loggerHolder atomically holds the current *zeroLogger.
type loggerHolder struct {
	current atomic.Pointer[zeroLogger]
}

func newLoggerHolder(l *zeroLogger) *loggerHolder {
	h := &loggerHolder{}
	h.current.Store(l)
	return h
}

func (h *loggerHolder) load() *zeroLogger { return h.current.Load() }

func (h *loggerHolder) store(l *zeroLogger) { h.current.Store(l) }

// Debug logs a debug message on the current logger.
func (h *loggerHolder) Debug(format string, args ...interface{}) {
	h.load().Debug(format, args...)
}

// Warn logs a warning on the current logger.
func (h *loggerHolder) Warn(format string, args ...interface{}) {
	h.load().Warn(format, args...)
}

// Error logs an error on the current logger.
func (h *loggerHolder) Error(format string, args ...interface{}) {
	h.load().Error(format, args...)
}

type zeroLogger struct {
	zeroLogger zerolog.Logger
}

func newLogger(debug bool) {
	logger.store(buildLogger(debug))
}

// buildLogger returns a fully configured logger. It must not be modified
// after it has been stored in logger.
func buildLogger(debug bool) *zeroLogger {
	// Skip frames: zerolog, zeroLogger method, loggerHolder method.
	l := &zeroLogger{zerolog.New(os.Stdout).With().CallerWithSkipFrameCount(4).Timestamp().Logger()}
	if debug {
		l.SetLevel(int8(zerolog.DebugLevel))
	} else {
		l.SetLevel(int8(zerolog.Disabled))
	}
	l.setOutput(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339Nano,
		FormatLevel: func(i interface{}) string {
			var l string
			lv, ok := i.(string)
			if !ok {
				return l
			}

			l, ok = formatLevel[lv]
			if ok {
				return l
			}
			return colorize(lv, colorBlue)
		},
	})
	return l
}

// colorize returns the string s wrapped in ANSI code c
func colorize(s interface{}, c int) string {
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m", c, s)
}

func (l *zeroLogger) setOutput(w io.Writer) {
	l.zeroLogger = l.zeroLogger.Output(w)
}

func (l *zeroLogger) SetLevel(v int8) {
	l.zeroLogger = l.zeroLogger.Level(zerolog.Level(v))
}

// Debug starts a new message with debug level.
// You must call Msg on the returned event in order to send the event.
func (l *zeroLogger) Debug(format string, args ...interface{}) {
	l.zeroLogger.Debug().Msgf(format, args...)
}

// Warn starts a new message with warn level.
// You must call Msg on the returned event in order to send the event.
func (l *zeroLogger) Warn(format string, args ...interface{}) {
	l.zeroLogger.Warn().Msgf(format, args...)
}

// Error starts a new message with error level.
// You must call Msg on the returned event in order to send the event.
func (l *zeroLogger) Error(format string, args ...interface{}) {
	l.zeroLogger.Error().Msgf(format, args...)
}
