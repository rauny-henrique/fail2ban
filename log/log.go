package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	output   io.Writer
	prefix   string
	logLevel LogLevel
	mu       sync.Mutex
}

type LogLevel string

func (l LogLevel) toInt() uint {
	switch LogLevel(strings.ToUpper(string(l))) {
	case Debug:
		return 0
	case Warning:
		return 2
	case Error:
		return 3
	default:
		return 1
	}
}

const (
	Info    LogLevel = "INFO"
	Debug   LogLevel = "DEBUG"
	Error   LogLevel = "ERROR"
	Warning LogLevel = "WARN"
)

func New(prefix string, level LogLevel) *Logger {
	return &Logger{
		output: os.Stdout,
		prefix: prefix,
	}
}

func (l *Logger) message(level LogLevel, msg string) {
	if level.toInt() < l.logLevel.toInt() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	m := fmt.Sprintf(
		"{\"prefix\": %q, \"level\": %q, \"msg\": %q, \"time\": %q}\n",
		l.prefix,
		level,
		msg,
		time.Now().Format("2006-01-02T15:04:05Z"),
	)
	l.output.Write([]byte(m))
}

func (l *Logger) Info(msg string) {
	l.Infof(msg)
}

func (l *Logger) Infof(msg string, args ...any) {
	l.message(Info, fmt.Sprintf(msg, args...))
}

func (l *Logger) Debug(msg string) {
	l.Debugf(msg)
}

func (l *Logger) Debugf(msg string, args ...any) {
	l.message(Debug, fmt.Sprintf(msg, args...))
}

func (l *Logger) Warn(msg string) {
	l.Warnf(msg)
}

func (l *Logger) Warnf(msg string, args ...any) {
	l.message(Warning, fmt.Sprintf(msg, args...))
}

func (l *Logger) Error(msg string) {
	l.Errorf(msg)
}

func (l *Logger) Errorf(msg string, args ...any) {
	l.message(Error, fmt.Sprintf(msg, args...))
}
