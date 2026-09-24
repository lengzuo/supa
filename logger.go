package supabase

import (
	"fmt"
	"io"
	"os"
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
	// logger defaults to a disabled logger so that components constructed
	// directly (NewAuth, NewPostgres, NewStorage) without New never hit a nil
	// logger. New replaces it according to Config.Debug.
	logger = buildLogger(false)
)

type zeroLogger struct {
	zeroLogger zerolog.Logger
}

func newLogger(debug bool) {
	logger = buildLogger(debug)
}

func buildLogger(debug bool) *zeroLogger {
	l := &zeroLogger{zerolog.New(os.Stdout).With().CallerWithSkipFrameCount(3).Timestamp().Logger()}
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
