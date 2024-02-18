package logger

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
	Logger *zeroLogger
)

type zeroLogger struct {
	zeroLogger zerolog.Logger
}

func New(debug bool) *zeroLogger {
	Logger = &zeroLogger{zerolog.New(os.Stdout).With().CallerWithSkipFrameCount(3).Timestamp().Logger()}
	if debug {
		Logger.SetLevel(int8(zerolog.DebugLevel))
	} else {
		Logger.SetLevel(int8(zerolog.Disabled))
	}
	Logger.setOutput(zerolog.ConsoleWriter{
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
	return Logger
}

// withPrefix set a tag to zeroLogger
func (l *zeroLogger) withPrefix(prefix string) {
	l.zeroLogger = l.zeroLogger.With().Str(Tag, prefix).Logger()
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
