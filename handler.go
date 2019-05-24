package frontman

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	log "github.com/sirupsen/logrus"
	ping "github.com/sparrc/go-ping"
)

var ErrorMissingHubOrInput = errors.New("Missing input file flag (-i) or hub_url param in config")

const timeoutDNSResolve = time.Second * 5

// serviceCheckEmergencyTimeout used to protect from unhandled timeouts
const serviceCheckEmergencyTimeout = time.Second * 30

func InputFromFile(filename string) (*Input, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("parseInputFromFile: '%s' failed to read the file: %s", filename, err.Error())
	}

	var i Input
	err = json.Unmarshal(b, &i)
	if err != nil {
		return nil, fmt.Errorf("parseInputFromFile: '%s' JSON unmarshal error: %s", filename, err.Error())
	}
	return &i, nil
}

func (fm *Frontman) initHubClient() {
	transport := &http.Transport{
		ResponseHeaderTimeout: 15 * time.Second,
	}
	if fm.rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{
			RootCAs: fm.rootCAs,
		}
	}
	if fm.Config.HubProxy != "" {
		if !strings.HasPrefix(fm.Config.HubProxy, "http://") {
			fm.Config.HubProxy = "http://" + fm.Config.HubProxy
		}
		proxyURL, err := url.Parse(fm.Config.HubProxy)
		if err != nil {
			log.WithFields(log.Fields{
				"url": fm.Config.HubProxy,
			}).Warningln("failed to parse hub_proxy URL")
		} else {
			if fm.Config.HubProxyUser != "" {
				proxyURL.User = url.UserPassword(fm.Config.HubProxyUser, fm.Config.HubProxyPassword)
			}
			transport.Proxy = func(_ *http.Request) (*url.URL, error) {
				return proxyURL, nil
			}
		}
	}
	fm.hubClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// CheckHubCredentials performs credentials check for a Hub config, returning errors that reference
// field names as in source config. Since config may be filled from file or UI, the field names can be different.
// Consider also localization of UI, we want to decouple credential checking logic from their actual view in UI.
//
// Examples:
// * for TOML: CheckHubCredentials(ctx, "hub_url", "hub_user", "hub_password")
// * for WinUI: CheckHubCredentials(ctx, "URL", "User", "Password")
func (fm *Frontman) CheckHubCredentials(ctx context.Context, fieldHubURL, fieldHubUser, fieldHubPassword string) error {
	fm.initHubClient()

	if fm.Config.HubURL == "" {
		return newEmptyFieldError(fieldHubURL)
	} else if u, err := url.Parse(fm.Config.HubURL); err != nil {
		err = errors.WithStack(err)
		return newFieldError(fieldHubURL, err)
	} else if u.Scheme != "http" && u.Scheme != "https" {
		err := errors.Errorf("wrong scheme '%s', URL must start with http:// or https://", u.Scheme)
		return newFieldError(fieldHubURL, err)
	}
	req, _ := http.NewRequest("HEAD", fm.Config.HubURL, nil)
	req.Header.Add("User-Agent", fm.userAgent())
	if fm.Config.HubUser != "" {
		req.SetBasicAuth(fm.Config.HubUser, fm.Config.HubPassword)
	}

	ctx, cancelFn := context.WithTimeout(ctx, time.Minute)
	req = req.WithContext(ctx)
	resp, err := fm.hubClient.Do(req)
	cancelFn()
	if err = fm.checkClientError(resp, err, fieldHubUser, fieldHubPassword); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (fm *Frontman) checkClientError(resp *http.Response, err error, fieldHubUser, fieldHubPassword string) error {
	if err != nil {
		if errors.Cause(err) == context.DeadlineExceeded {
			err = errors.New("connection timeout, please check your proxy or firewall settings")
			return err
		}
		return err
	}
	_, _ = io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		if fm.Config.HubUser == "" {
			return newEmptyFieldError(fieldHubUser)
		} else if fm.Config.HubPassword == "" {
			return newEmptyFieldError(fieldHubPassword)
		}
		err := errors.Errorf("unable to authorize with provided Hub credentials (HTTP %d)", resp.StatusCode)
		return err
	} else if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		err := errors.Errorf("unable to authorize with provided Hub credentials (HTTP %d)", resp.StatusCode)
		return err
	}
	return nil
}

func newEmptyFieldError(name string) error {
	err := errors.Errorf("unexpected empty field %s", name)
	return errors.Wrap(err, "the field must be filled with details of your Cloudradar account")
}

func newFieldError(name string, err error) error {
	return errors.Wrapf(err, "%s field verification failed", name)
}

func (fm *Frontman) InputFromHub() (*Input, error) {
	fm.initHubClient()

	if fm.Config.HubURL == "" {
		return nil, newEmptyFieldError("hub_url")
	} else if u, err := url.Parse(fm.Config.HubURL); err != nil {
		err = errors.WithStack(err)
		return nil, newFieldError("hub_url", err)
	} else if u.Scheme != "http" && u.Scheme != "https" {
		err := errors.Errorf("wrong scheme '%s', URL must start with http:// or https://", u.Scheme)
		return nil, newFieldError("hub_url", err)
	}

	i := Input{}
	r, err := http.NewRequest("GET", fm.Config.HubURL, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Add("User-Agent", fm.userAgent())

	if fm.Config.HubUser != "" {
		r.SetBasicAuth(fm.Config.HubUser, fm.Config.HubPassword)
	}

	resp, err := fm.hubClient.Do(r)
	if err != nil {
		fm.Stats.HubLastErrorMessage = err.Error()
		fm.Stats.HubLastErrorTimestamp = uint64(time.Now().Second())
		fm.Stats.HubErrorsTotal++
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.New(resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &i)
	if err != nil {
		return nil, err
	}

	// Update frontman statistics
	fm.Stats.BytesFetchedFromHubTotal += uint64(len(body))
	fm.Stats.ChecksFetchedFromHub += uint64(len(i.ServiceChecks)) + uint64(len(i.WebChecks)) + uint64(len(i.SNMPChecks))

	return &i, nil
}

func (fm *Frontman) PostResultsToHub(results []Result) error {
	fm.initHubClient()

	fm.offlineResultsBuffer = append(fm.offlineResultsBuffer, results...)
	b, err := json.Marshal(Results{
		Results: fm.offlineResultsBuffer,
	})

	if err != nil {
		return err
	}

	// in case we have HubMaxOfflineBufferBytes set(>0) and buffer + results exceed HubMaxOfflineBufferBytes -> reset buffer
	if fm.Config.HubMaxOfflineBufferBytes > 0 && len(b) > fm.Config.HubMaxOfflineBufferBytes && len(fm.offlineResultsBuffer) > 0 {
		log.Errorf("hub_max_offline_buffer_bytes(%d bytes) exceed with %d results. Flushing the buffer...",
			fm.Config.HubMaxOfflineBufferBytes,
			len(results))

		fm.offlineResultsBuffer = []Result{}
		b, err = json.Marshal(Results{Results: results})
		if err != nil {
			return err
		}
	}

	if fm.Config.HubURL == "" {
		return newEmptyFieldError("hub_url")
	} else if u, err := url.Parse(fm.Config.HubURL); err != nil {
		err = errors.WithStack(err)
		return newFieldError("hub_url", err)
	} else if u.Scheme != "http" && u.Scheme != "https" {
		err := errors.Errorf("wrong scheme '%s', URL must start with http:// or https://", u.Scheme)
		return newFieldError("hub_url", err)
	}

	var req *http.Request
	var bodyLength int

	if fm.Config.HubGzip {
		var buffer bytes.Buffer
		zw := gzip.NewWriter(&buffer)
		zw.Write(b)
		zw.Close()
		req, err = http.NewRequest("POST", fm.Config.HubURL, &buffer)
		bodyLength = buffer.Len()
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req, err = http.NewRequest("POST", fm.Config.HubURL, bytes.NewBuffer(b))
		bodyLength = len(b)
	}
	if err != nil {
		return err
	}

	req.Header.Add("User-Agent", fm.userAgent())

	if fm.Config.HubUser != "" {
		req.SetBasicAuth(fm.Config.HubUser, fm.Config.HubPassword)
	}

	resp, err := fm.hubClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	log.Debugf("Sent %d results to Hub.. Status %d", len(results), resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return errors.New(resp.Status)
	}

	// in case of successful POST reset the offline buffer
	fm.offlineResultsBuffer = []Result{}

	// Update frontman statistics
	fm.Stats.BytesSentToHubTotal += uint64(bodyLength)

	return nil
}

func (fm *Frontman) sendResultsChanToFileContinuously(resultsChan chan Result, outputFile *os.File) error {
	var errs []string
	var jsonEncoder = json.NewEncoder(outputFile)

	// encode and add results to the file as we get it from the chan
	for res := range resultsChan {
		err := jsonEncoder.Encode(res)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	if errs != nil {
		return fmt.Errorf("JSON encoding errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

func (fm *Frontman) sendResultsChanToFile(resultsChan chan Result, outputFile *os.File) error {
	var results []Result
	var jsonEncoder = json.NewEncoder(outputFile)
	for res := range resultsChan {
		results = append(results, res)
	}

	return jsonEncoder.Encode(results)
}

func (fm *Frontman) sendResultsChanToHub(resultsChan chan Result) error {
	var results []Result
	for res := range resultsChan {
		results = append(results, res)
	}
	err := fm.PostResultsToHub(results)
	if err != nil {
		return fmt.Errorf("PostResultsToHub: %s", err.Error())
	}

	fm.Stats.CheckResultsSentToHub += uint64(len(results))

	fm.offlineResultsBuffer = []Result{}
	return nil
}

func (fm *Frontman) sendResultsChanToHubWithInterval(resultsChan chan Result) error {
	sendResultsTicker := time.NewTicker(secToDuration(fm.Config.SenderModeInterval))
	defer sendResultsTicker.Stop()

	var results []Result
	shouldReturn := false

	for {
		select {
		case res, ok := <-resultsChan:
			if !ok {
				// chan was closed
				// no more results left
				shouldReturn = true
				break
			}

			results = append(results, res)
			// skip PostResultsToHub
			continue
		case <-sendResultsTicker.C:
			break
		}

		log.Debugf("SenderModeInterval: send %d results", len(results))
		err := fm.PostResultsToHub(results)
		if err != nil {
			err = fmt.Errorf("PostResultsToHub error: %s", err.Error())
		}

		if shouldReturn {
			return err
		}

		if err != nil {
			log.Error(err)
		}
	}
}

// HealthCheck runs before any other check to ensure that the host itself and its network are healthly.
// This is useful to confirm a stable internet connection to avoid false alerts due to network outages.
func (fm *Frontman) HealthCheck() error {
	hcfg := fm.Config.HealthChecks
	if len(hcfg.ReferencePingHosts) == 0 {
		return nil
	}
	if hcfg.ReferencePingCount == 0 {
		return nil
	}
	timeout := secToDuration(hcfg.ReferencePingTimeout)
	if timeout == 0 {
		// use the default timeout
		timeout = 500 * time.Millisecond
	}
	failC := make(chan string, len(hcfg.ReferencePingHosts))

	wg := new(sync.WaitGroup)
	for _, addr := range hcfg.ReferencePingHosts {
		p, err := ping.NewPinger(addr)
		if err != nil {
			log.WithError(err).Warningln("failed to parse host for ICMP ping")
			continue
		}
		p.Timeout = timeout
		p.Count = hcfg.ReferencePingCount
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			p.Run()
			if p.Statistics().PacketLoss > 0 {
				failC <- addr
			}
		}(addr)
	}
	go func() {
		wg.Wait()
		close(failC)
	}()

	failedHosts := []string{}
	for host := range failC {
		failedHosts = append(failedHosts, host)
	}
	if len(failedHosts) > 0 {
		return fmt.Errorf("host(s) failed to respond to ICMP ping: %s", strings.Join(failedHosts, ", "))
	}
	return nil
}

func (fm *Frontman) RunOnce(input *Input, outputFile *os.File, interrupt chan struct{}, writeResultsChanToFileContinously bool) error {
	var err error
	var hostInfo MeasurementsMap

	// in case HUB server will hang on response we will need a buffer to continue perform checks
	resultsChan := make(chan Result, 100)

	// since fm.Run calls fm.RunOnce over and over again, we need this check here
	if !fm.hostInfoSent {
		// Only try to collect HostInfo when HostInfo or SystemFields are defined in config
		fields := joinStrings(fm.Config.HostInfo, fm.Config.SystemFields)
		if len(fields) > 0 {
			hostInfo, err = fm.HostInfoResults()
			if err != nil {
				log.Warnf("Failed to fetch HostInfo: %s", err)
				hostInfo["error"] = err.Error()
			}
		}

		// Send hostInfo as first result
		resultsChan <- Result{
			Measurements: hostInfo,
			CheckType:    "hostInfo",
			Timestamp:    time.Now().Unix(),
		}
		fm.hostInfoSent = true
	}

	wg := new(sync.WaitGroup)
	defer wg.Wait()
	if input != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fm.processInput(input, resultsChan)
		}()
	} else {
		close(resultsChan)
	}

	if outputFile != nil && writeResultsChanToFileContinously {
		err = fm.sendResultsChanToFileContinuously(resultsChan, outputFile)
	} else if outputFile != nil {
		err = fm.sendResultsChanToFile(resultsChan, outputFile)
	} else if fm.Config.SenderMode == SenderModeInterval {
		err = fm.sendResultsChanToHubWithInterval(resultsChan)
	} else if fm.Config.SenderMode == SenderModeWait {
		err = fm.sendResultsChanToHub(resultsChan)
	}

	if err != nil {
		return fmt.Errorf("Failed to process results: %s", err.Error())
	}

	return nil
}

func (fm *Frontman) FetchInput(inputFilePath string) (*Input, error) {
	var input *Input
	var err error

	if inputFilePath != "" {
		input, err = InputFromFile(inputFilePath)
		if err != nil {
			return nil, errors.Wrapf(err, "InputFromFile(%s) error", inputFilePath)
		}
		return input, nil
	}

	if fm.Config.HubURL == "" {
		return nil, ErrorMissingHubOrInput
	}

	// in case input file not specified this means we should request HUB instead
	input, err = fm.InputFromHub()
	if err != nil {
		if fm.Config.HubUser != "" {
			// it may be useful to log the Hub User that was used to do a HTTP Basic Auth
			// e.g. in case of '401 Unauthorized' user can see the corresponding user in the logs
			return nil, errors.Wrapf(err, "InputFromHub(%s:***) error", fm.Config.HubUser)
		}
		return nil, errors.Wrap(err, "InputFromHub error")
	}

	return input, nil
}

func (fm *Frontman) Run(inputFilePath string, outputFile *os.File, interrupt chan struct{}) {
	fm.Stats.StartedAt = time.Now()
	log.Debugf("Start writing stats file: %s", fm.Config.StatsFile)
	fm.StartWritingStats()

	for {
		if err := fm.HealthCheck(); err != nil {
			fm.HealthCheckPassedPreviously = false
			log.WithError(err).Errorln("Health checks are not passed. Skipping other checks.")
			select {
			case <-interrupt:
				return
			case <-time.After(secToDuration(fm.Config.Sleep)):
				continue
			}
		} else if !fm.HealthCheckPassedPreviously {
			fm.HealthCheckPassedPreviously = true
			log.Infoln("All health checks are positive. Resuming normal operation.")
		}

		input, err := fm.FetchInput(inputFilePath)
		if err != nil && err == ErrorMissingHubOrInput {
			log.Warnln(err)
			// This is necessary because MSI does not respect if service quits with status 0 but quickly.
			// In other cases this delay doesn't matter, but also can be useful for polling config changes in a loop.
			time.Sleep(10 * time.Second)
			os.Exit(0)
		} else if err != nil {
			log.Error(err)
		} else {
			err := fm.RunOnce(input, outputFile, interrupt, false)
			if err != nil {
				log.Error(err)
			}
		}

		select {
		case <-interrupt:
			return
		case <-time.After(secToDuration(fm.Config.Sleep)):
			continue
		}
	}
}

func (fm *Frontman) runServiceCheck(check ServiceCheck) (map[string]interface{}, error) {
	done := make(chan struct{})
	defer func() {
		close(done)
	}()

	var err error
	var results map[string]interface{}
	checkLog := log.WithFields(log.Fields{
		"uuid": check.UUID,
	})

	go func() {
		// Calling the routine using uniquify object will guarantee that
		// only one instance of a check with same UUID is running, even if there was a leak.
		err = fm.uniquify.Call(check.UUID, func() error {
			ipaddr, resolveErr := resolveIPAddrWithTimeout(check.Check.Connect, timeoutDNSResolve)
			if resolveErr != nil {
				checkLog.WithError(resolveErr).Debugln("serviceCheck: resolveIPAddr failed")
				return errors.Wrap(resolveErr, "resolveIPAddr failed")
			}

			switch check.Check.Protocol {
			case ProtocolICMP:
				if res, pingErr := fm.runPing(ipaddr); pingErr != nil {
					checkLog.WithError(pingErr).Debugln("serviceCheck: runPing failed")
					return errors.Wrap(pingErr, "runPing failed")
				} else {
					results = res
				}
			case ProtocolTCP:
				port, _ := check.Check.Port.Int64()
				addr := &net.TCPAddr{
					IP:   ipaddr.IP,
					Port: int(port),
				}
				if res, tcpErr := fm.runTCPCheck(addr, check.Check.Connect, check.Check.Service); tcpErr != nil {
					checkLog.WithError(tcpErr).Debugln("serviceCheck: tcpCheck failed")
					return errors.Wrap(tcpErr, "tcpCheck failed")
				} else {
					results = res
				}
			case ProtocolSSL:
				port, _ := check.Check.Port.Int64()
				addr := &net.TCPAddr{
					IP:   ipaddr.IP,
					Port: int(port),
				}
				if res, sslErr := fm.runSSLCheck(addr, check.Check.Connect, check.Check.Service); sslErr != nil {
					checkLog.WithError(sslErr).Debugln("serviceCheck: sslCheck failed")
					return errors.Wrap(sslErr, "sslCheck failed")
				} else {
					results = res
				}
			case "":
				checkLog.Errorf("serviceCheck: missing check.protocol")
				return errors.New("Missing check.protocol")
			default:
				checkLog.WithField("check.protocol", check.Check.Protocol).
					Errorf("serviceCheck: unknown check.protocol")
				return errors.New("Unknown check.protocol")
			}
			return nil
		})
	}()

	// Warning: do not rely on serviceCheckEmergencyTimeout as it leak goroutines(until it will be finished)
	// instead use individual timeouts inside all checks
	select {
	case <-done:
		return results, err
	case <-time.After(serviceCheckEmergencyTimeout):
		secs := serviceCheckEmergencyTimeout.Seconds()
		checkLog.Errorf("serviceCheck: got unexpected timeout after %.0fs", secs)
		return nil, errors.New("got unexpected timeout")
	}
}

func (fm *Frontman) processInput(input *Input, resultsChan chan<- Result) {
	wg := new(sync.WaitGroup)
	startedAt := time.Now()
	succeed := 0

	seenServiceChecks := make(map[string]struct{}, len(input.ServiceChecks))

	for _, check := range input.ServiceChecks {
		if check.UUID == "" {
			log.Errorf("serviceCheck: missing checkUuid key")
			continue
		} else if _, ok := seenServiceChecks[check.UUID]; ok {
			continue
		}
		seenServiceChecks[check.UUID] = struct{}{}

		checkLog := log.WithFields(log.Fields{
			"uuid": check.UUID,
		})

		wg.Add(1)
		go func(check ServiceCheck) {
			defer wg.Done()

			res := Result{
				CheckType: "serviceCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check.Check

			if check.Check.Connect == "" {
				checkLog.Errorf("serviceCheck: missing data.connect key")
				res.Message = "Missing data.connect key"
			} else if result, err := fm.runServiceCheck(check); err != nil {
				res.Message = err.Error()
			} else {
				res.Measurements = result
				succeed++
			}
			resultsChan <- res
		}(check)
	}

	seenWebChecks := make(map[string]struct{}, len(input.WebChecks))

	for _, check := range input.WebChecks {
		if check.UUID == "" {
			log.Errorf("webCheck: missing checkUuid key")
			continue
		} else if _, ok := seenWebChecks[check.UUID]; ok {
			continue
		}
		seenWebChecks[check.UUID] = struct{}{}

		checkLog := log.WithFields(log.Fields{
			"uuid": check.UUID,
		})

		wg.Add(1)
		go func(check WebCheck) {
			defer wg.Done()

			res := Result{
				CheckType: "webCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check.Check

			if check.Check.Method == "" {
				checkLog.Errorf("webCheck: missing check.method key")
				res.Message = "Missing check.method key"
			} else if check.Check.URL == "" {
				checkLog.Errorf("webCheck: missing check.url key")
				res.Message = "Missing check.url key"
			} else {
				var result map[string]interface{}
				// Calling the routine using uniquify object will guarantee that
				// only one instance of a check with same UUID is running, even if there was a leak.
				if err := fm.uniquify.Call(check.UUID, func() error {
					if res, checkErr := fm.runWebCheck(check.Check); checkErr != nil {
						return errors.Wrap(checkErr, "runWebCheck failed")
					} else {
						result = res
					}
					return nil
				}); err != nil {
					checkLog.WithError(err).Debugln("webCheck failed")
					res.Message = err.Error()
				} else {
					res.Measurements = result
				}
			}

			if res.Message == nil {
				succeed++
			}

			resultsChan <- res
		}(check)
	}

	for _, check := range input.SNMPChecks {
		wg.Add(1)
		go func(check SNMPCheck) {
			defer wg.Done()

			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				log.Errorf("snmpCheck: missing checkUuid key")
				return
			}

			res := Result{
				CheckType: "snmpCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check.Check

			if check.Check.Connect == "" {
				log.Errorf("snmpCheck: missing check.connect key")
				res.Message = "Missing check.connect key"
			} else {
				var err error
				res.Measurements, err = fm.runSNMPCheck(&check)
				if err != nil {
					log.Debugf("snmpCheck: %s: %s", check.UUID, err.Error())
					res.Message = err.Error()
				}
			}

			if res.Message == nil {
				succeed++
			}

			resultsChan <- res
		}(check)
	}

	wg.Wait()
	close(resultsChan)

	totChecks := len(input.ServiceChecks) + len(input.WebChecks) + len(input.SNMPChecks)
	log.Infof("%d/%d checks succeed in %.1f sec", succeed, totChecks, time.Since(startedAt).Seconds())
}

// HostInfoResults fetches information about the host itself which can be
// send to the hub alongside measurements.
func (fm *Frontman) HostInfoResults() (MeasurementsMap, error) {
	res := MeasurementsMap{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	info, err := host.InfoWithContext(ctx)
	errs := []string{}

	if err != nil {
		log.Errorf("[SYSTEM] Failed to read host info: %s", err.Error())
		errs = append(errs, err.Error())
	}

	fields := joinStrings(fm.Config.HostInfo, fm.Config.SystemFields)
	for _, field := range fields {
		switch strings.ToLower(field) {
		case "os_kernel":
			if info != nil {
				res[field] = info.OS
			} else {
				res[field] = nil
			}
		case "os_family":
			if info != nil {
				res[field] = info.PlatformFamily
			} else {
				res[field] = nil
			}
		case "uname":
			uname, err := Uname()
			if err != nil {
				log.Errorf("[SYSTEM] Failed to read host uname: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
			} else {
				res[field] = uname
			}
		case "fqdn":
			res[field] = getFQDN()
		case "cpu_model":
			cpuInfo, err := cpu.Info()
			if err != nil {
				log.Errorf("[SYSTEM] Failed to read cpu info: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}

			res[field] = cpuInfo[0].ModelName
		case "os_arch":
			res[field] = runtime.GOARCH
		case "memory_total_b":
			memStat, err := mem.VirtualMemory()
			if err != nil {
				log.Errorf("[SYSTEM] Failed to read mem info: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}

			res[field] = memStat.Total
		}
	}

	if len(errs) == 0 {
		return res, nil
	}

	return res, errors.New("SYSTEM: " + strings.Join(errs, "; "))
}

func resolveIPAddrWithTimeout(addr string, timeout time.Duration) (*net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, addr)
	if err != nil {
		return nil, err
	}

	if len(ipAddrs) == 0 {
		return nil, errors.New("can't resolve host")
	}

	ipAddr := ipAddrs[0]
	return &ipAddr, nil
}

func joinStrings(a, b []string) []string {
	ab := make([]string, 0, len(a)+len(b))
	set := make(map[string]struct{}, len(ab))
	for _, str := range a {
		set[str] = struct{}{}
	}
	for _, str := range b {
		set[str] = struct{}{}
	}
	for str := range set {
		ab = append(ab, str)
	}
	return ab
}
