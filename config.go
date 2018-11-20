package frontman

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"bytes"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

const (
	IOModeFile = "file"
	IOModeHTTP = "http"

	SenderModeWait     = "wait"
	SenderModeInterval = "interval"
)

var DefaultCfgPath string

type Frontman struct {
	Sleep float64 `toml:"sleep"` // delay before starting a new round of checks in seconds

	PidFile   string   `toml:"pid"`
	LogFile   string   `toml:"log"`
	LogSyslog string   `toml:"log_syslog"` // "local" for local unix socket or URL e.g. "udp://localhost:514" for remote syslog server
	LogLevel  LogLevel `toml:"log_level"`

	IOMode                   string `toml:"io_mode"` // "file" or "http" – where frontman gets checks to perform and post results
	HubURL                   string `toml:"hub_url"`
	HubGzip                  bool   `toml:"hub_gzip"` // enable gzip when sending results to the HUB
	HubUser                  string `toml:"hub_user"`
	HubPassword              string `toml:"hub_password"`
	HubProxy                 string `toml:"hub_proxy"`
	HubProxyUser             string `toml:"hub_proxy_user"`
	HubProxyPassword         string `toml:"hub_proxy_password"`
	HubMaxOfflineBufferBytes int    `toml:"hub_max_offline_buffer_bytes"`

	ICMPTimeout            float64 `toml:"icmp_timeout"`        // ICMP ping timeout in seconds
	NetTCPTimeout          float64 `toml:"net_tcp_timeout"`     // TCP timeout in seconds
	HTTPCheckTimeout       float64 `toml:"http_check_time_out"` // HTTP time in seconds
	HTTPCheckMaxRedirects  int     `toml:"max_redirects"`       // Limit the number of HTTP redirects to follow
	IgnoreSSLErrors        bool    `toml:"ignore_ssl_errors"`
	SSLCertExpiryThreshold int     `toml:"ssl_cert_expiry_threshold"` // Min days remain on the SSL cert to pass the check

	SenderMode         string  `toml:"sender_mode"`          // "wait" – to post results to HUB after each round; "interval" – to post results to HUB by fixed interval
	SenderModeInterval float64 `toml:"sender_mode_interval"` // interval in seconds to post results to HUB server

	// Will be sent to hub as HostInfo
	SystemFields []string `toml:"system_fields"`

	// internal use
	httpTransport *http.Transport
	hubHttpClient *http.Client
	hostInfoSent  bool

	offlineResultsBuffer []Result

	rootCAs *x509.CertPool
	version string
}

func New() *Frontman {
	var defaultLogPath string
	var rootCertsPath string

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	switch runtime.GOOS {
	case "windows":
		DefaultCfgPath = filepath.Join(exPath, "./frontman.conf")
		defaultLogPath = filepath.Join(exPath, "./frontman.log")
	case "darwin":
		DefaultCfgPath = os.Getenv("HOME") + "/.frontman/frontman.conf"
		defaultLogPath = os.Getenv("HOME") + "/.frontman/frontman.log"
	default:
		rootCertsPath = "/etc/frontman/cacert.pem"
		DefaultCfgPath = "/etc/frontman/frontman.conf"
		defaultLogPath = "/var/log/frontman/frontman.log"
	}

	fm := &Frontman{
		IOMode:                 "http",
		LogFile:                defaultLogPath,
		ICMPTimeout:            0.1,
		Sleep:                  30,
		SenderMode:             SenderModeWait,
		HTTPCheckMaxRedirects:  10,
		HTTPCheckTimeout:       15,
		NetTCPTimeout:          3,
		SSLCertExpiryThreshold: 7,
		SystemFields:           []string{},
		hostInfoSent:           false,
	}

	if rootCertsPath != "" {
		if _, err := os.Stat(rootCertsPath); err == nil {
			certPool := x509.NewCertPool()

			b, err := ioutil.ReadFile(rootCertsPath)
			if err != nil {
				log.Error("Failed to read cacert.pem: ", err.Error())
			} else {
				ok := certPool.AppendCertsFromPEM(b)
				if ok {
					fm.rootCAs = certPool
				}
			}
		}
	}

	if fm.HubURL == "" {
		fm.HubURL = os.Getenv("FRONTMAN_HUB_URL")
	}

	if fm.HubUser == "" {
		fm.HubUser = os.Getenv("FRONTMAN_HUB_USER")
	}

	if fm.HubPassword == "" {
		fm.HubPassword = os.Getenv("FRONTMAN_HUB_PASSWORD")
	}

	return fm
}

func secToDuration(secs float64) time.Duration {
	return time.Duration(int64(float64(time.Second) * secs))
}

func (fm *Frontman) SetVersion(version string) {
	fm.version = version
}

func (fm *Frontman) userAgent() string {
	if fm.version == "" {
		fm.version = "{undefined}"
	}
	parts := strings.Split(fm.version, "-")

	return fmt.Sprintf("Frontman v%s %s %s", parts[0], runtime.GOOS, runtime.GOARCH)
}

func (fm *Frontman) DumpConfigToml() string {
	buff := &bytes.Buffer{}
	enc := toml.NewEncoder(buff)
	err := enc.Encode(fm)

	if err != nil {
		log.Errorf("DumpConfigToml error: %s", err.Error())
	}

	return buff.String()
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

	if fm.HubProxy != "" {
		if !strings.HasPrefix(fm.HubProxy, "http") {
			fm.HubProxy = "http://" + fm.HubProxy
		}
		_, err := url.Parse(fm.HubProxy)
		if err != nil {
			return fmt.Errorf("Failed to parse 'hub_proxy' URL")
		}
	}

	if fm.LogFile != "" {
		err := addLogFileHook(fm.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Error("Can't write logs to file: ", err.Error())
		}
	}

	if fm.LogSyslog != "" {
		err := addSyslogHook(fm.LogSyslog)
		if err != nil {
			log.Error("Can't set up syslog: ", err.Error())
		}
	}
	return nil
}
