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
	"time"

	"github.com/cloudradar-monitoring/selfupdate"
	"github.com/kardianos/service"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman/pkg/stats"
)

// variables set on build. Example:
// go build -o frontman -ldflags="-X main.Version=$(git --git-dir=src/github.com/cloudradar-monitoring/frontman/.git describe --always --long --dirty --tag)" github.com/cloudradar-monitoring/frontman/cmd/frontman
var (
	Version            string
	SelfUpdatesFeedURL = "https://repo.cloudradar.io/windows/frontman/feed/rolling"
)

type Frontman struct {
	Config         *Config
	ConfigLocation string

	stats     *stats.FrontmanStats
	statsLock sync.Mutex

	HealthCheckPassedPreviously bool

	selfUpdater *selfupdate.Updater

	hubClient    *http.Client
	hostInfoSent bool

	// local cached results in case the hub is temporarily offline
	offlineResultsBuffer []Result
	offlineResultsLock   sync.Mutex

	rootCAs *x509.CertPool
	version string

	failedNodeLock  sync.Mutex
	failedNodes     map[string]time.Time
	failedNodeCache map[string][]byte

	forwardLog *os.File

	serviceConfig service.Config

	// current checks queue
	checks     []Check
	checksLock sync.RWMutex

	// in-progress checks
	ipc inProgressChecks

	// completed check results to be sent to hub
	results     []Result
	resultsLock sync.RWMutex

	previousSNMPBandwidthMeasure  []snmpBandwidthMeasure
	previousSNMPOidDeltaMeasure   []snmpOidDeltaMeasure
	previousSNMPPorterrorsMeasure []snmpPorterrorsMeasure

	TerminateQueue sync.WaitGroup
}

func New(cfg *Config, cfgPath, version string) (*Frontman, error) {
	if version == "" {
		version = "{undefined}"
	}
	fm := &Frontman{
		Config:                      cfg,
		ConfigLocation:              cfgPath,
		stats:                       &stats.FrontmanStats{},
		HealthCheckPassedPreviously: true,
		hostInfoSent:                false,
		version:                     version,
		failedNodes:                 make(map[string]time.Time),
		failedNodeCache:             make(map[string][]byte),
		TerminateQueue:              sync.WaitGroup{},
		ipc:                         newIPC(),
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

	if err := fm.Config.sanitize(); err != nil {
		logrus.Error(err)
	}

	fm.configureLogger()

	fm.initHubClient()

	err := fm.configureAutomaticSelfUpdates()
	if err != nil {
		logrus.Error(err.Error())
		return nil, err
	}

	return fm, nil
}

func (fm *Frontman) configureAutomaticSelfUpdates() error {
	if !fm.Config.Updates.Enabled {
		return nil
	}
	updatesConfig := selfupdate.DefaultConfig()
	updatesConfig.AppName = "frontman"
	updatesConfig.SigningCertificatedName = "cloudradar GmbH"
	updatesConfig.CurrentVersion = Version
	updatesConfig.CheckInterval = fm.Config.Updates.GetCheckInterval()
	updatesConfig.UpdatesFeedURL = fm.Config.Updates.URL
	logrus.Debugf("using %s as self-updates feed URL", updatesConfig.UpdatesFeedURL)

	err := selfupdate.Configure(updatesConfig)
	if err != nil {
		return errors.Wrapf(err, "invalid configuration for self-update")
	}

	selfupdate.SetLogger(logrus.StandardLogger())

	return nil
}

// returns an user agent string
func (fm *Frontman) userAgent() string {
	parts := strings.Split(fm.version, "-")
	return fmt.Sprintf("Frontman v%s %s %s", parts[0], runtime.GOOS, runtime.GOARCH)
}
