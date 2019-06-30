package frontman

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudradar-monitoring/frontman/pkg/stats"
	"github.com/sirupsen/logrus"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelError LogLevel = "error"
)

func (lvl LogLevel) LogrusLevel() logrus.Level {
	switch lvl {
	case LogLevelDebug:
		return logrus.DebugLevel
	case LogLevelError:
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}

type logrusFileHook struct {
	file      *os.File
	flag      int
	chmod     os.FileMode
	formatter *logrus.TextFormatter
}

func addLogFileHook(file string, flag int, chmod os.FileMode) error {
	dir := filepath.Dir(file)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create the logs dir: '%s'", dir)
	}

	plainFormatter := &logrus.TextFormatter{FullTimestamp: true, DisableColors: true}
	logFile, err := os.OpenFile(file, flag, chmod)
	if err != nil {
		return fmt.Errorf("unable to write log file: %s", err.Error())
	}

	hook := &logrusFileHook{logFile, flag, chmod, plainFormatter}

	logrus.AddHook(hook)

	return nil
}

func addErrorHook(stats *stats.FrontmanStats) {
	hook := &LogrusErrorHook{
		InternalErrorsTotal:        &stats.InternalErrorsTotal,
		InternalLastErrorMessage:   &stats.InternalLastErrorMessage,
		InternalLastErrorTimestamp: &stats.InternalLastErrorTimestamp,
	}

	logrus.AddHook(hook)
}

// Fire event
func (hook *logrusFileHook) Fire(entry *logrus.Entry) error {
	plainformat, err := hook.formatter.Format(entry)
	if err != nil {
		return err
	}
	line := string(plainformat)
	_, err = hook.file.WriteString(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to write file on filehook(entry.String)%v", err)
		return err
	}
	return nil
}

func (hook *logrusFileHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

// StartWritingStats writes fm.Stats every minute to Config.StatsFile
// This method should only be called once
func (fm *Frontman) StartWritingStats() {
	var stats stats.FrontmanStats
	var buff bytes.Buffer
	var err error

	// Make the output indented
	encoder := json.NewEncoder(&buff)
	encoder.SetIndent("", "    ")

	// Only start writing out stats if there is a StatsFile configued
	if fm.Config.StatsFile != "" {
		go func() {
			for {
				buff.Reset()
				time.Sleep(time.Minute * 1)
				stats.Uptime = uint64(time.Since(stats.StartedAt).Seconds())
				// Get snapshot from current stats
				stats = *fm.Stats
				err = encoder.Encode(stats)
				if err != nil {
					logrus.Errorf("Could not encode stats file: %s", err)
					continue
				}

				err = ioutil.WriteFile(fm.Config.StatsFile, buff.Bytes(), 0755)
				if err != nil {
					logrus.Errorf("Could not write stats file: %s", err)
					return
				}
			}
		}()
	}
}

// SetLogLevel sets Log level and corresponding logrus level
func (fm *Frontman) SetLogLevel(lvl LogLevel) {
	fm.Config.LogLevel = lvl
	logrus.SetLevel(lvl.LogrusLevel())
}

type LogrusErrorHook struct {
	InternalErrorsTotal        *uint64
	InternalLastErrorMessage   *string
	InternalLastErrorTimestamp *uint64
}

func (h *LogrusErrorHook) Fire(entry *logrus.Entry) error {
	now := uint64(time.Now().Unix())

	*h.InternalErrorsTotal++
	*h.InternalLastErrorMessage = entry.Message
	*h.InternalLastErrorTimestamp = now

	return nil
}

func (h *LogrusErrorHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.ErrorLevel,
	}
}

func (fm *Frontman) configureLogger() {
	tfmt := logrus.TextFormatter{FullTimestamp: true, DisableColors: true}
	logrus.SetFormatter(&tfmt)

	fm.SetLogLevel(fm.Config.LogLevel)

	if fm.Config.LogFile != "" {
		err := addLogFileHook(fm.Config.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			logrus.Error("Can't write logs to file: ", err.Error())
		}
	}
	if fm.Config.LogSyslog != "" {
		err := addSyslogHook(fm.Config.LogSyslog)
		if err != nil {
			logrus.Error("Can't set up syslog: ", err.Error())
		}
	}

	// Add hook to logrus that updates our LastInternalError statistics
	// whenever an error log is done
	addErrorHook(fm.Stats)

	// sets standard logging to /dev/null
	devNull, err := os.OpenFile(os.DevNull, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		logrus.Error("err", err)
	}
	logrus.SetOutput(devNull)
}
