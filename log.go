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
	log "github.com/sirupsen/logrus"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelError LogLevel = "error"
)

func (lvl LogLevel) LogrusLevel() log.Level {
	switch lvl {
	case LogLevelDebug:
		return log.DebugLevel
	case LogLevelError:
		return log.ErrorLevel
	default:
		return log.InfoLevel
	}
}

type logrusFileHook struct {
	file      *os.File
	flag      int
	chmod     os.FileMode
	formatter *log.TextFormatter
}

func addLogFileHook(file string, flag int, chmod os.FileMode) error {
	dir := filepath.Dir(file)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		log.WithError(err).Errorf("Failed to create the logs dir: '%s'", dir)
	}

	plainFormatter := &log.TextFormatter{FullTimestamp: true, DisableColors: true}
	logFile, err := os.OpenFile(file, flag, chmod)
	if err != nil {
		return fmt.Errorf("Unable to write log file: %s", err.Error())
	}

	hook := &logrusFileHook{logFile, flag, chmod, plainFormatter}

	log.AddHook(hook)

	return nil
}

func addErrorHook(stats *stats.FrontmanStats) {
	hook := &LogrusErrorHook{
		InternalErrorsTotal:        &stats.InternalErrorsTotal,
		InternalLastErrorMessage:   &stats.InternalLastErrorMessage,
		InternalLastErrorTimestamp: &stats.InternalLastErrorTimestamp,
	}

	log.AddHook(hook)
}

// Fire event
func (hook *logrusFileHook) Fire(entry *log.Entry) error {
	plainformat, err := hook.formatter.Format(entry)
	line := string(plainformat)
	_, err = hook.file.WriteString(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to write file on filehook(entry.String)%v", err)
		return err
	}

	return nil
}

func (hook *logrusFileHook) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	}
}

// StartWritingStats writes fm.Stats every minute to Config.StatsFile
func (fm *Frontman) StartWritingStats() {
	var stats stats.FrontmanStats
	var buff bytes.Buffer
	var err error

	go func() {
		for {
			time.Sleep(time.Minute * 1)
			// Get snapshot from current stats
			stats = *fm.Stats
			err = json.NewEncoder(&buff).Encode(stats)
			if err != nil {
				log.Errorf("Could not encode stats file: %s", err)
				continue
			}

			err = ioutil.WriteFile(fm.Config.StatsFile, buff.Bytes(), 0755)
			if err != nil {
				// TODO: should we return in this case? Or after 5 times or...?
				log.Errorf("Could not write stats file: %s", err)
			}
		}
	}()
}

// SetLogLevel sets Log level and corresponding logrus level
func (fm *Frontman) SetLogLevel(lvl LogLevel) {
	fm.Config.LogLevel = lvl
	log.SetLevel(lvl.LogrusLevel())
}

type LogrusErrorHook struct {
	InternalErrorsTotal        *uint64
	InternalLastErrorMessage   *string
	InternalLastErrorTimestamp *uint64
}

func (h *LogrusErrorHook) Fire(entry *log.Entry) error {
	now := uint64(time.Now().Unix())

	*h.InternalErrorsTotal++
	*h.InternalLastErrorMessage = entry.Message
	*h.InternalLastErrorTimestamp = now

	return nil
}

func (h *LogrusErrorHook) Levels() []log.Level {
	return []log.Level{
		log.ErrorLevel,
	}
}
