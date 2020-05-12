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

// variables set on build. Example:
// go build -o frontman -ldflags="-X main.Version=$(git --git-dir=src/github.com/cloudradar-monitoring/frontman/.git describe --always --long --dirty --tag)" github.com/cloudradar-monitoring/frontman/cmd/frontman
var (
	Version            string
)

type Frontman struct {
	Config         *Config
	ConfigLocation string

	Stats                       *stats.FrontmanStats
	HealthCheckPassedPreviously bool

	hubClient     *http.Client
	hubClientOnce sync.Once
	hostInfoSent  bool

	offlineResultsBuffer []Result

	rootCAs *x509.CertPool
	version string

	previousSNMPBandwidthMeasure  []snmpBandwidthMeasure
	previousSNMPOidDeltaMeasure   []snmpOidDeltaMeasure
	previousSNMPPorterrorsMeasure []snmpPorterrorsMeasure
}

func New(cfg *Config, cfgPath, version string) (*Frontman, error) {
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
	return fm, nil
}

func (fm *Frontman) userAgent() string {
	if fm.version == "" {
		fm.version = "{undefined}"
	}
	parts := strings.Split(fm.version, "-")

	return fmt.Sprintf("Frontman v%s %s %s", parts[0], runtime.GOOS, runtime.GOARCH)
}
