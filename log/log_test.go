package log

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestLogging(t *testing.T) {
	logger := New("test", Debug)
	buff := bytes.Buffer{}
	logger.output = &buff

	expectedResults := []string{
		`{"prefix": "test", "level": "DEBUG", "msg": "message: test_debugf", "time": "202`,
		`{"prefix": "test", "level": "INFO", "msg": "message: test_infof", "time": "202`,
		`{"prefix": "test", "level": "WARN", "msg": "message: test_warnf", "time": "202`,
		`{"prefix": "test", "level": "ERROR", "msg": "message: test_errorf", "time": "202`,
		`{"prefix": "test", "level": "DEBUG", "msg": "message: test_debug", "time": "202`,
		`{"prefix": "test", "level": "INFO", "msg": "message: test_info", "time": "202`,
		`{"prefix": "test", "level": "WARN", "msg": "message: test_warn", "time": "202`,
		`{"prefix": "test", "level": "ERROR", "msg": "message: test_error", "time": "202`,
	}

	logger.Debugf("message: %s", "test_debugf")
	logger.Infof("message: %s", "test_infof")
	logger.Warnf("message: %s", "test_warnf")
	logger.Errorf("message: %s", "test_errorf")

	logger.Debug("message: test_debug")
	logger.Info("message: test_info")
	logger.Warn("message: test_warn")
	logger.Error("message: test_error")

	data, err := io.ReadAll(&buff)
	if err != nil {
		t.Errorf("Failed to read buffer %q", err)
	}

	// Split on newline, last log will be empty
	logs := strings.Split(string(data), "\n")
	if len(logs) != 9 && logs[8] != "" {
		t.Errorf("Unexpected number of logs %d", len(logs))
	}
	logs = logs[:8]

	for idx, result := range logs {
		if !strings.Contains(result, expectedResults[idx]) {
			t.Errorf(`Expected %q, got %q`, expectedResults[idx], result)
		}
	}
}

func TestLoggingWithLevel(t *testing.T) {
	logger := New("test", Warning)
	buff := bytes.Buffer{}
	logger.output = &buff

	expectedResults := []string{
		`{"prefix": "test", "level": "WARN", "msg": "message: test_warnf", "time": "202`,
		`{"prefix": "test", "level": "ERROR", "msg": "message: test_errorf", "time": "202`,
		`{"prefix": "test", "level": "WARN", "msg": "message: test_warn", "time": "202`,
		`{"prefix": "test", "level": "ERROR", "msg": "message: test_error", "time": "202`,
	}

	logger.Debugf("message: %s", "test_debugf")
	logger.Infof("message: %s", "test_infof")
	logger.Warnf("message: %s", "test_warnf")
	logger.Errorf("message: %s", "test_errorf")

	logger.Debug("message: test_debug")
	logger.Info("message: test_info")
	logger.Warn("message: test_warn")
	logger.Error("message: test_error")

	data, err := io.ReadAll(&buff)
	if err != nil {
		t.Errorf("Failed to read buffer %q", err)
	}

	// Split on newline, last log will be empty
	logs := strings.Split(string(data), "\n")
	if len(logs) != 5 && logs[4] != "" {
		t.Errorf("Unexpected number of logs %d", len(logs))
	}
	logs = logs[:4]

	for idx, result := range logs {
		if !strings.Contains(result, expectedResults[idx]) {
			t.Errorf(`Expected %q, got %q`, expectedResults[idx], result)
		}
	}
}

func TestLevelChecker(t *testing.T) {
	levels := []LogLevel{
		Debug,
		Info,
		Warning,
		Error,
	}
	for idx, level := range levels[1:] {
		if levels[idx].toInt() > level.toInt() {
			t.Errorf("Detected level %q higher than %q", levels[idx], level)
		}
	}
	if LogLevel("garbage").toInt() != Info.toInt() {
		t.Error("Default level is INFO")
	}
}
