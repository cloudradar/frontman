package frontman

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Frontman struct {
	Config *Config

	// internal use
	httpTransport *http.Transport
	hubHTTPClient *http.Client
	hostInfoSent  bool

	offlineResultsBuffer []Result

	rootCAs *x509.CertPool
	version string
}

func New(version string, cfg *Config) *Frontman {
	fm := &Frontman{
		Config:       cfg,
		hostInfoSent: false,
		version:      version,
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

	if fm.Config.LogFile != "" {
		err := addLogFileHook(fm.Config.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Error("Can't write logs to file: ", err.Error())
		}
	}

	if fm.Config.LogSyslog != "" {
		err := addSyslogHook(fm.Config.LogSyslog)
		if err != nil {
			log.Error("Can't set up syslog: ", err.Error())
		}
	}

	return fm
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
