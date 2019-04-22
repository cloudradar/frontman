package frontman

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman/pkg/stats"
)

type Frontman struct {
	Config         *Config
	ConfigLocation string

	Stats                *stats.FrontmanStats
	HealthCheckNotPassed bool

	httpTransport *http.Transport
	hubClient     *http.Client
	hubClientOnce sync.Once
	hostInfoSent  bool

	offlineResultsBuffer []Result

	rootCAs *x509.CertPool
	version string
}

func New(cfg *Config, cfgPath, version string) *Frontman {
	fm := &Frontman{
		Config:         cfg,
		ConfigLocation: cfgPath,
		Stats:          &stats.FrontmanStats{},
		hostInfoSent:   false,
		version:        version,
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

	fm.initHttpTransport()

	// Add hook to logrus that updates our LastInternalError statistics
	// whenever an error log is done
	addErrorHook(fm.Stats)

	return fm
}

func (fm *Frontman) userAgent() string {
	if fm.version == "" {
		fm.version = "{undefined}"
	}
	parts := strings.Split(fm.version, "-")

	return fmt.Sprintf("Frontman v%s %s %s", parts[0], runtime.GOOS, runtime.GOARCH)
}
