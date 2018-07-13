package frontman

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
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

	plainFormatter := &log.TextFormatter{DisableColors: true}
	logFile, err := os.OpenFile(file, flag, chmod)
	if err != nil {
		return fmt.Errorf("Unable to write log file: %s", err.Error())
	}

	hook := &logrusFileHook{logFile, flag, chmod, plainFormatter}

	tfmt := log.TextFormatter{FullTimestamp: true}
	log.SetFormatter(&tfmt)
	log.AddHook(hook)

	return nil
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

// Sets Log level and corresponding logrus level
func (fm *Frontman) SetLogLevel(lvl LogLevel) {
	fm.LogLevel = lvl
	log.SetLevel(lvl.LogrusLevel())
}
