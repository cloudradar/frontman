package frontman

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cloudradar-monitoring/selfupdate"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ErrorMissingHubOrInput  = errors.New("Missing input file flag (-i) or hub_url param in config")
	ErrorHubGeneral         = errors.New("Hub replied with a general error code")
	ErrorHubTooManyRequests = errors.New("Hub replied with a 429 error code")
)

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
			logrus.WithFields(logrus.Fields{
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
		Timeout:   time.Duration(fm.Config.HubRequestTimeout) * time.Second,
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

	var responseBody string
	responseBodyBytes, readBodyErr := ioutil.ReadAll(resp.Body)
	if readBodyErr == nil {
		responseBody = string(responseBodyBytes)
	}

	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		if fm.Config.HubUser == "" {
			return newEmptyFieldError(fieldHubUser)
		} else if fm.Config.HubPassword == "" {
			return newEmptyFieldError(fieldHubPassword)
		}
		return errors.Errorf("unable to authorize with provided Hub credentials (HTTP %d). %s", resp.StatusCode, responseBody)
	} else if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		return errors.Errorf("got unexpected response from server (HTTP %d). %s", resp.StatusCode, responseBody)
	}
	return nil
}

func (fm *Frontman) inputFromHub() (*Input, error) {
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
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			err = fmt.Errorf("hub request timeout of %d seconds exceeded", fm.Config.HubRequestTimeout)
			err = errors.Wrap(err, netErr.Error())
		}

		fm.Stats.HubLastErrorMessage = err.Error()
		fm.Stats.HubLastErrorTimestamp = uint64(time.Now().Second())
		fm.Stats.HubErrorsTotal++
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		logrus.Debugf("inputFromHub failed: hub replied with error %s", resp.Status)
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, ErrorHubTooManyRequests
		}
		if resp.StatusCode >= 400 {
			return nil, ErrorHubGeneral
		}
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

func (fm *Frontman) Run(inputFilePath string, outputFile *os.File, interrupt chan struct{}) {
	fm.Stats.StartedAt = time.Now()
	logrus.Debugf("Start writing stats file: %s", fm.Config.StatsFile)
	fm.StartWritingStats()

	if fm.Config.Updates.Enabled {
		fm.selfUpdater = selfupdate.StartChecking()
	}
	defer func() {
		if fm.selfUpdater != nil {
			fm.selfUpdater.Shutdown()
		}
	}()

	for {
		if err := fm.HealthCheck(); err != nil {
			fm.HealthCheckPassedPreviously = false
			logrus.WithError(err).Errorln("Health checks are not passed. Skipping other checks.")
			select {
			case <-interrupt:
				return
			case <-time.After(secToDuration(fm.Config.Sleep)):
				continue
			}
		} else if !fm.HealthCheckPassedPreviously {
			fm.HealthCheckPassedPreviously = true
			logrus.Infoln("All health checks are positive. Resuming normal operation.")
		}

		input, err := fm.FetchInput(inputFilePath)
		switch {
		case err != nil && err == ErrorMissingHubOrInput:
			logrus.Warnln(err)
			// This is necessary because MSI does not respect if service quits with status 0 but quickly.
			// In other cases this delay doesn't matter, but also can be useful for polling config changes in a loop.
			time.Sleep(10 * time.Second)
			os.Exit(0)
		case err != nil && err == ErrorHubGeneral:
			logrus.Warnln("ErrorHubGeneral", err)
			// sleep until the next data submission is due
			fm.sleepUntilNextInterval()

		case err != nil && err == ErrorHubTooManyRequests:
			logrus.Warnln(err)
			// for error code 429, wait 10 seconds and try again
			time.Sleep(10 * time.Second)
		case err != nil:
			logrus.Error(err)
		default:
			if err := fm.RunOnce(input, outputFile, interrupt, false); err != nil {
				logrus.Error(err)
			}
		}

		select {
		case <-interrupt:
			return
		default:
			continue
		}
	}
}

func (fm *Frontman) RunOnce(input *Input, outputFile *os.File, interrupt chan struct{}, writeResultsChanToFileContinously bool) error {
	var err error
	var hostInfo MeasurementsMap

	// in case HUB server will hang on response we will need a buffer to continue perform checks
	resultsChan := make(chan Result, 100)

	// since fm.Run calls fm.RunOnce over and over again, we need this check here
	if !fm.hostInfoSent {
		// Only try to collect HostInfo when defined in config
		if len(fm.Config.HostInfo) > 0 {
			hostInfo, err = fm.HostInfoResults()
			if err != nil {
				logrus.Warnf("Failed to fetch HostInfo: %s", err)
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

	if input != nil {
		go fm.processInput(input, resultsChan)
	} else {
		close(resultsChan)
	}

	switch {
	case outputFile != nil && writeResultsChanToFileContinously:
		logrus.Debugf("sender_mode sendResultsChanToFileContinuously")
		err = fm.sendResultsChanToFileContinuously(resultsChan, outputFile)
	case outputFile != nil:
		logrus.Debugf("sender_mode sendResultsChanToFile")
		err = fm.sendResultsChanToFile(resultsChan, outputFile)
	case fm.Config.SenderMode == SenderModeInterval:
		logrus.Debugf("sender_mode INTERVAL")
		err = fm.sendResultsChanToHubWithInterval(resultsChan)
	case fm.Config.SenderMode == SenderModeWait:
		logrus.Debugf("sender_mode WAIT")
		sleepTime := secToDuration(fm.Config.Sleep)
		start := time.Now()
		err = fm.sendResultsChanToHub(resultsChan)
		sleepTime -= time.Since(start)
		if sleepTime > 0 {
			time.Sleep(sleepTime)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to process results: %s", err.Error())
	}

	return nil
}

func (fm *Frontman) FetchInput(inputFilePath string) (*Input, error) {
	var input *Input
	var err error

	if inputFilePath != "" {
		input, err = InputFromFile(inputFilePath)
		if err != nil {
			return nil, fmt.Errorf("InputFromFile(%s) error: %s", inputFilePath, err.Error())
		}
		return input, nil
	}

	if fm.Config.HubURL == "" {
		return nil, ErrorMissingHubOrInput
	}

	// in case input file not specified this means we should request HUB instead
	input, err = fm.inputFromHub()
	if err != nil {
		if err == ErrorHubGeneral || err == ErrorHubTooManyRequests {
			return nil, err
		}
		if fm.Config.HubUser != "" {
			// it may be useful to log the Hub User that was used to do a HTTP Basic Auth
			// e.g. in case of '401 Unauthorized' user can see the corresponding user in the logs
			return nil, fmt.Errorf("inputFromHub(%s:***): %s", fm.Config.HubUser, err.Error())
		}
		return nil, fmt.Errorf("inputFromHub: %s", err.Error())
	}

	return input, nil
}

func (fm *Frontman) processInput(input *Input, resultsChan chan<- Result) {
	wg := sync.WaitGroup{}
	startedAt := time.Now()

	succeed := runServiceChecks(fm, &wg, resultsChan, input.ServiceChecks)
	succeed += runWebChecks(fm, &wg, resultsChan, input.WebChecks)
	succeed += runSNMPChecks(fm, &wg, resultsChan, input.SNMPChecks)

	wg.Wait()
	close(resultsChan)

	totChecks := len(input.ServiceChecks) + len(input.WebChecks) + len(input.SNMPChecks)
	fm.Stats.ChecksPerformedTotal += uint64(totChecks)
	logrus.Infof("%d/%d checks succeed in %.1f sec", succeed, totChecks, time.Since(startedAt).Seconds())
}

// Used in case of hub failure. Sleeps for the configured interval according to sender_mode INTERVAL/WAIT configuration
func (fm *Frontman) sleepUntilNextInterval() {
	if fm.Config.SenderMode == SenderModeInterval {
		delay := secToDuration(fm.Config.SenderModeInterval)
		logrus.Debugf("sleepUntilNextInterval INTERVAL sleeping for %v", delay)
		time.Sleep(delay)
	}
	if fm.Config.SenderMode == SenderModeWait {
		delay := secToDuration(fm.Config.Sleep)
		logrus.Debugf("sleepUntilNextInterval WAIT sleeping for %v", delay)
		time.Sleep(delay)
	}
}
