package frontman

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cloudradar-monitoring/toml"
	"github.com/sirupsen/logrus"
)

const (
	defaultLogLevel = "error"

	IOModeFile = "file"
	IOModeHTTP = "http"

	SenderModeWait     = "wait"
	SenderModeInterval = "interval"

	minHubRequestTimeout     = 1
	maxHubRequestTimeout     = 600
	defaultHubRequestTimeout = 30
)

var configAutogeneratedHeadline = []byte(
	`# This is an auto-generated config to connect with the cloudradar service
# To see all options of frontman run frontman -p
#
`)

var DefaultCfgPath string
var defaultLogPath string
var rootCertsPath string
var defaultStatsFilePath string

type MinValuableConfig struct {
	LogLevel    LogLevel `toml:"log_level" comment:"\"debug\", \"info\", \"error\" verbose level; can be overridden with -v flag"`
	IOMode      string   `toml:"io_mode" comment:"\"file\" or \"http\" – where frontman gets checks to perform and post results"`
	HubURL      string   `toml:"hub_url" commented:"true"`
	HubUser     string   `toml:"hub_user" commented:"true"`
	HubPassword string   `toml:"hub_password" commented:"true"`

	HubProxy         string `toml:"hub_proxy" commented:"true"`
	HubProxyUser     string `toml:"hub_proxy_user" commented:"true"`
	HubProxyPassword string `toml:"hub_proxy_password" commented:"true"`

	// new configs should use host_info, keep system_fields to support older configs
	SystemFields []string `toml:"system_fields" commented:"true" comment:"DEPRECATED: use host_info instead"`
	HostInfo     []string `toml:"host_info" commented:"true"`
}

type Config struct {
	NodeName  string  `toml:"node_name" comment:"Name of the Frontman\nUsed to identify group measurements if multiple frontmen run in grouped-mode (ask_nodes)"`
	Sleep     float64 `toml:"sleep" comment:"delay before starting a new round of checks in second\nsleep refers to the start timestamp of the check round.\nIf sleep is 30 seconds and the round takes 25 seconds frontman waits 5 seconds to start the next round.\nIf sleep is less than the round takes, there is no delay."`
	PidFile   string  `toml:"pid" comment:"path to pid file"`
	LogFile   string  `toml:"log,omitempty" comment:"path to log file"`
	LogSyslog string  `toml:"log_syslog" comment:"\"local\" for local unix socket or URL e.g. \"udp://localhost:514\" for remote syslog server"`
	StatsFile string  `toml:"stats_file" comment:"Path to the file where we write frontman statistics"`

	MinValuableConfig

	HubGzip                  bool `toml:"hub_gzip" comment:"enable gzip when sending results to the HUB"`
	HubRequestTimeout        int  `toml:"hub_request_timeout" comment:"time limit in seconds for requests made to Hub.\nThe timeout includes connection time, any redirects, and reading the response body.\nMin: 1, Max: 600. default: 30"`
	HubMaxOfflineBufferBytes int  `toml:"hub_max_offline_buffer_bytes" commented:"true"`

	ICMPTimeout            float64 `toml:"icmp_timeout" comment:"ICMP ping timeout in seconds"`
	NetTCPTimeout          float64 `toml:"net_tcp_timeout" comment:"TCP timeout in seconds"`
	HTTPCheckTimeout       float64 `toml:"http_check_timeout" comment:"HTTP time in seconds"`
	HTTPCheckMaxRedirects  int     `toml:"max_redirects" comment:"Limit the number of HTTP redirects to follow"`
	IgnoreSSLErrors        bool    `toml:"ignore_ssl_errors"`
	SSLCertExpiryThreshold int     `toml:"ssl_cert_expiry_threshold" comment:"Min days remain on the SSL cert to pass the check"`

	SenderMode string `toml:"sender_mode" comment:"sender_mode = \"wait\" waits for all checks to finish.\n
Results are sent back and # frontman sleeps the sleep interval.\n
If the round has taken more than the sleep interval the next round starts immediately.\n\n
sender_mode = \"interval\"\n
Frontman fetches the list of checks and performs the checks.\n
After the given period of sender_mode_interval frontman detaches from all checks\n
not finished yet and sends back what it has collected. The unfinished checks keep running.\n
During the next round, all checks which are still running from the previous round\n
are skipped to avoid double runs of checks.\n
If during the start of frontman \"sender_mode\" is "interval" and \"sender_mode_interval\" is larger\n
than sleep frontman throws an error and denies starting because it would cause congestion."`
	SenderModeInterval float64 `toml:"sender_mode_interval" comment:"interval in seconds to post results to HUB server\nrequires sender_mode = \"interval\", ignored on sender_mode = \"wait\""`

	HealthChecks HealthCheckConfig `toml:"health_checks" comment:"Frontman can verify a reliable internet uplink by pinging some reference hosts before each check round starts.\nPing all hosts of the list.\nOnly if frontman gets a positive answer form all of them, frontman continues.\nOtherwise, the entire check round is skipped. No data is sent back.\nFailed health checks are recorded to the log.\nOnly 0% packet loss is considered as a positive check result. Pings are performed in parallel.\nDisabled by default. Enable by declaring reference_ping_hosts targets\n"`

	HTTPListener HTTPListenerConfig `toml:"http_listener" comment:"Perform checks requested via HTTP POST requests"`

	FailureConfirmation      int     `toml:"failure_confirmation" comment:"In case a web or service check fails, frontman will check again after a short delay (seconds). The failure must be confirmed N times.\nfailure_confirmation = 0 switches off the confirmation of failures\nDoes not affect snmp checks"`
	FailureConfirmationDelay float64 `toml:"failure_confirmation_delay" comment:"Delay in seconds"`

	Nodes map[string]Node `toml:"nodes" comment:"Frontman can execute a failed check on other frontmen - ideally on different locations -\nto confirm the check fails everywhere.\nOnly if the check fails on all of them it's considered as failed and sent back to the hub.\nIf the check succeeds on one frontman this check result is sent back\nRequires the HTTP listener enabled on the foreign frontman\nExample:\n[nodes]\n  [nodes.1]\n  url = \"https://frontman-1.example.com:9955\"\n  username = \"frontman\"\n  password = \"secret\"\n  verify_ssl = true"`
}

type Node struct {
	URL       string `toml:"url" comment:"URL of frontman node"`
	Username  string `toml:"username" comment:"Username"`
	Password  string `toml:"password" comment:"Password"`
	VerifySSL bool   `toml:"verify_ssl"`
}

type HealthCheckConfig struct {
	ReferencePingHosts   []string `toml:"reference_ping_hosts" comment:"Ping all hosts of the list. Only if frontman gets a positive answer form all of them, frontman continues.\nOnly 0% packet loss is considered as a positive check result. Pings are performed in parallel."`
	ReferencePingTimeout float64  `toml:"reference_ping_timeout" comment:"Maximum time (seconds) to wait for the response"`
	ReferencePingCount   int      `toml:"reference_ping_count" comment:"Number of request packets to send to each host."`
}

type HTTPListenerConfig struct {
	HTTPListen       string `toml:"http_listen" comment:"HTTP Listener\nPerform checks requested via HTTP POST requests on '/check'\nExamples:\nhttp_listen = \"http://0.0.0.0:9090\"   # for unencrypted http connections\nhttp_listen = \"https://0.0.0.0:8443\"  # for encrypted https connections\nexecute \"sudo setcap cap_net_bind_service=+ep /usr/bin/frontman\" to use ports < 1024\nExecuting SNMP check through the HTTP Listener is not supported."`
	HTTPTLSKey       string `toml:"http_tls_key" comment:"Private key for https connections"`
	HTTPTLSCert      string `toml:"http_tls_cert" comment:"Certificate for https connections"`
	HTTPAuthUser     string `toml:"http_auth_user" comment:"Username for the http basic authentication. If omitted authentication is disabled"`
	HTTPAuthPassword string `toml:"http_auth_password" comment:"Password for the http basic authentication."`
	HTTPAccessLog    string `toml:"http_access_log" comment:"Log http requests. On windows slash must be escaped like \"C:\\\\access.log\""`
}

func init() {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	switch runtime.GOOS {
	case "windows":
		DefaultCfgPath = filepath.Join(exPath, "./frontman.conf")
		defaultLogPath = filepath.Join(exPath, "./frontman.log")
		defaultStatsFilePath = "C:\\Windows\\temp\\frontman.stats"
	case "darwin":
		DefaultCfgPath = os.Getenv("HOME") + "/.frontman/frontman.conf"
		defaultLogPath = os.Getenv("HOME") + "/.frontman/frontman.log"
		defaultStatsFilePath = "/tmp/frontman.stats"
	default:
		rootCertsPath = "/etc/frontman/cacert.pem"
		DefaultCfgPath = "/etc/frontman/frontman.conf"
		defaultLogPath = "/var/log/frontman/frontman.log"
		defaultStatsFilePath = "/tmp/frontman.stats"
	}
}

func NewConfig() *Config {
	cfg := &Config{
		MinValuableConfig:      *NewMinimumConfig(),
		NodeName:               "Frontman",
		LogFile:                defaultLogPath,
		StatsFile:              defaultStatsFilePath,
		ICMPTimeout:            0.1,
		Sleep:                  30,
		SenderMode:             SenderModeInterval,
		SenderModeInterval:     20,
		HTTPCheckMaxRedirects:  10,
		HTTPCheckTimeout:       15,
		NetTCPTimeout:          3,
		SSLCertExpiryThreshold: 7,
		HealthChecks: HealthCheckConfig{
			ReferencePingTimeout: 1,
			ReferencePingCount:   1,
		},
		HubRequestTimeout: defaultHubRequestTimeout,
	}
	return cfg
}

func NewMinimumConfig() *MinValuableConfig {
	mvc := &MinValuableConfig{
		IOMode:       IOModeHTTP,
		LogLevel:     defaultLogLevel,
		SystemFields: []string{},
		HostInfo:     []string{"uname", "os_kernel", "os_family", "os_arch", "cpu_model", "fqdn", "memory_total_B"},
	}
	mvc.applyEnv(false)
	return mvc
}

func secToDuration(secs float64) time.Duration {
	return time.Duration(int64(float64(time.Second) * secs))
}

func (mvc *MinValuableConfig) applyEnv(force bool) {
	if val, ok := os.LookupEnv("FRONTMAN_HUB_URL"); ok && ((mvc.HubURL == "") || force) {
		mvc.HubURL = val
	}
	if val, ok := os.LookupEnv("FRONTMAN_HUB_USER"); ok && ((mvc.HubUser == "") || force) {
		mvc.HubUser = val
	}
	if val, ok := os.LookupEnv("FRONTMAN_HUB_PASSWORD"); ok && ((mvc.HubPassword == "") || force) {
		mvc.HubPassword = val
	}
}

func (cfg *Config) DumpToml() string {
	buff := &bytes.Buffer{}
	enc := toml.NewEncoder(buff)
	err := enc.Encode(cfg)

	if err != nil {
		logrus.Errorf("DumpConfigToml error: %s", err.Error())
		return ""
	}

	return buff.String()
}

// TryUpdateConfigFromFile applies values from file in configFilePath to cfg if given file exists.
// it rewrites all cfg keys that present in the file
func (cfg *Config) TryUpdateConfigFromFile(configFilePath string) error {
	_, err := os.Stat(configFilePath)
	if err != nil {
		return err
	}

	_, err = toml.DecodeFile(configFilePath, cfg)
	return err
}

// SaveConfigFile saves config file as toml
func SaveConfigFile(mvc *MinValuableConfig, configFilePath string) error {
	f, err := os.Create(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to open the config file '%s': %s", configFilePath, err.Error())
	}
	defer f.Close()

	if _, err = f.Write(configAutogeneratedHeadline); err != nil {
		return fmt.Errorf("failed to write headline to config file")
	}

	err = toml.NewEncoder(f).Encode(mvc)
	if err != nil {
		return fmt.Errorf("failed to encode config to file")
	}

	return nil
}

// GenerateDefaultConfigFile creates a default frontman.toml and writes to to disk
func GenerateDefaultConfigFile(mvc *MinValuableConfig, configFilePath string) error {
	var err error

	if _, err = os.Stat(configFilePath); os.IsExist(err) {
		return fmt.Errorf("config already exists at path: %s", configFilePath)
	}

	absFile, err := filepath.Abs(configFilePath)
	if err != nil {
		return err
	}
	path := filepath.Dir(absFile)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return SaveConfigFile(mvc, configFilePath)
}

// auto-corrects some config values
func (cfg *Config) fixup() error {
	if cfg.HubProxy != "" {
		if !strings.HasPrefix(cfg.HubProxy, "http") {
			cfg.HubProxy = "http://" + cfg.HubProxy
		}

		if _, err := url.Parse(cfg.HubProxy); err != nil {
			return fmt.Errorf("failed to parse 'hub_proxy' URL")
		}
	}

	if cfg.HubRequestTimeout < minHubRequestTimeout || cfg.HubRequestTimeout > maxHubRequestTimeout {
		cfg.HubRequestTimeout = defaultHubRequestTimeout
		return fmt.Errorf("hub_request_timeout must be between %d and %d", minHubRequestTimeout, maxHubRequestTimeout)
	}

	if cfg.SenderModeInterval <= 0 {
		cfg.SenderModeInterval = 30
	}

	// backwards compatibility with old configs. system_fields is deprecated!
	cfg.HostInfo = append(cfg.HostInfo, cfg.SystemFields...)

	return nil
}

// HandleAllConfigSetup prepares config for Frontman with parameters specified in file
// if config file not exists default one created in form of MinValuableConfig
func HandleAllConfigSetup(configFilePath string) (*Config, error) {
	cfg := NewConfig()

	err := cfg.TryUpdateConfigFromFile(configFilePath)
	if os.IsNotExist(err) {
		mvc := NewMinimumConfig()
		if err = GenerateDefaultConfigFile(mvc, configFilePath); err != nil {
			return nil, err
		}

		cfg.MinValuableConfig = *mvc
	} else if err != nil {
		if strings.Contains(err.Error(), "cannot load TOML value of type int64 into a Go float") {
			return nil, fmt.Errorf("config load '%s' error: please use numbers with a decimal point for numerical values", configFilePath)
		}

		return nil, fmt.Errorf("config load '%s' error: %s", configFilePath, err.Error())
	}

	return cfg, nil
}
