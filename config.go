package frontman

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

const (
	IOModeFile = "file"
	IOModeHTTP = "http"

	SenderModeWait     = "wait"
	SenderModeInterval = "interval"
)

type Frontman struct {
	Sleep float64 `toml:"sleep"` // delay before starting a new round of checks in seconds

	LogFile  string   `toml:"log"`
	LogLevel LogLevel `toml:"log_level"`

	IOMode      string `toml:"io_mode"` // "file" or "http" – where frontman gets checks to perform and post results
	HubURL      string `toml:"hub_url"`
	HubUser     string `toml:"hub_user"`
	HubPassword string `toml:"hub_password"`

	ICMPTimeout            float64 `toml:"icmp_timeout"`        // ICMP ping timeout in seconds
	NetTCPTimeout          float64 `toml:"net_tcp_timeout"`     // TCP timeout in seconds
	HTTPCheckTimeout       float64 `toml:"http_check_time_out"` // HTTP time in seconds
	HTTPCheckMaxRedirects  int     `toml:"max_redirects"`       // Limit the number of HTTP redirects to follow
	IgnoreSSLErrors        bool    `toml:"ignore_ssl_errors"`
	SSLCertExpiryThreshold float64 `toml:"ssl_cert_expiry_threshold"` // Min days remain on the SSL cert to pass the check

	SenderMode         string  `toml:"sender_mode"`          // "wait" – to post results to HUB after each round; "interval" – to post results to HUB by fixed interval
	SenderModeInterval float64 `toml:"sender_mode_interval"` // interval in seconds to post results to HUB server

	// internal use
	httpTransport *http.Transport
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
		LogFile:                "/tmp/frontman.log",
		ICMPTimeout:            0.1,
		Sleep:                  30,
		SenderMode:             SenderModeWait,
		HTTPCheckMaxRedirects:  10,
		HTTPCheckTimeout:       15,
		SSLCertExpiryThreshold: 7,
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

		if err != nil {
			return fmt.Errorf("Failed to create the default config file: '%s'", configFilePath)
		}
		defer f.Close()
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
