package frontman

import (
	"fmt"
	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Frontman struct {
	LogFile     string   `toml:"log"`
	LogLevel    LogLevel `toml:"log_level"`
	ICMPTimeout float64  `toml:"icmp_timeout"`
	Sleep       float64  `toml:"sleep"`

	// can be set only with flags
	OneRunOnly bool `toml:"-"`
}

var DefaultCfgPath string

func New() *Frontman {
	var defaultLogPath string

	switch runtime.GOOS {
	case "windows":
		DefaultCfgPath = "./frontman.conf"
		defaultLogPath = "./frontman.log"
	case "darwin":
		DefaultCfgPath = os.Getenv("HOME") + "/.frontman/frontman.conf"
		defaultLogPath = os.Getenv("HOME") + "/.frontman/frontman.log"
	default:
		DefaultCfgPath = "/etc/frontman/frontman.conf"
		defaultLogPath = "/tmp/frontman.log"
	}

	fm := &Frontman{
		LogFile:     "/tmp/frontman.log",
		ICMPTimeout: 0.1,
		Sleep:       5,
	}

	fm.SetLogLevel(LogLevelInfo)

	fm.LogFile = defaultLogPath
	return fm
}

func secToDuration(secs float64) time.Duration {
	return time.Duration(int64(float64(time.Second) * secs))
}

func (fm *Frontman) ReadConfigFromFile(configFilePath string, createIfNotExists bool) error {
	dir := filepath.Dir(configFilePath)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		log.WithError(err).Errorf("Failed to create the config dir: '%s'", dir)
	}

	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		if !createIfNotExists {
			return fmt.Errorf("Config file not exists: %s", configFilePath)
		}
		f, err := os.OpenFile(configFilePath, os.O_WRONLY|os.O_CREATE, 0644)
		defer f.Close()

		if err != nil {
			log.WithError(err).Errorf("Failed to create the default config file: '%s'", configFilePath)
		}
		enc := toml.NewEncoder(f)
		enc.Encode(fm)

	} else {
		_, err = os.Stat(configFilePath)
		if err != nil {
			return err
		}
		_, err = toml.DecodeFile(configFilePath, &fm)

		if err != nil {
			return err
		}
	}

	fm.SetLogLevel(fm.LogLevel)
	return addLogFileHook(fm.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
}
