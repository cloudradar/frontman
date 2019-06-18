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

	"github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman/pkg/stats"
)

type Frontman struct {
	Config         *Config
	ConfigLocation string

	Stats                       *stats.FrontmanStats
	HealthCheckPassedPreviously bool

	httpTransport *http.Transport
	hubClient     *http.Client
	hubClientOnce sync.Once
	hostInfoSent  bool

	offlineResultsBuffer []Result

	rootCAs *x509.CertPool
	version string

	previousSNMPBandwidthMeasure []snmpBandwidthMeasure
	previousSNMPOidDeltaMeasure  []snmpOidDeltaMeasure
}

func New(cfg *Config, cfgPath, version string) *Frontman {
	fm := &Frontman{
		Config:                      cfg,
		ConfigLocation:              cfgPath,
		Stats:                       &stats.FrontmanStats{},
		HealthCheckPassedPreviously: true,
		hostInfoSent:                false,
		version:                     version,
	}

	if rootCertsPath != "" {
		if _, err := os.Stat(rootCertsPath); err == nil {
			certPool := x509.NewCertPool()

			b, err := ioutil.ReadFile(rootCertsPath)
			if err != nil {
				logrus.Error("Failed to read cacert.pem: ", err.Error())
			} else {
				ok := certPool.AppendCertsFromPEM(b)
				if ok {
					fm.rootCAs = certPool
				}
			}
		}
	}

	if err := fm.Config.fixup(); err != nil {
		logrus.Error(err)
	}

	fm.configureLogger()

	fm.initHttpTransport()

	return fm
}

func (fm *Frontman) userAgent() string {
	if fm.version == "" {
		fm.version = "{undefined}"
	}
	parts := strings.Split(fm.version, "-")

	return fmt.Sprintf("Frontman v%s %s %s", parts[0], runtime.GOOS, runtime.GOARCH)
}
