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

// Run runs all checks continuously and sends result to hub or file
func (fm *Frontman) Run(inputFilePath string, outputFile *os.File, interrupt chan struct{}, resultsChan chan Result) {

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

	if !fm.hostInfoSent {
		var err error
		var hostInfo MeasurementsMap

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

	go fm.processInputContinuous(inputFilePath, true, interrupt, &resultsChan)

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

		if err := fm.sendResultsChanToHubQueue(&resultsChan); err != nil {
			logrus.Error(err)
		}

		select {
		case <-interrupt:
			return
		default:
			continue
		}
	}
}

// RunOnce runs all checks once and send result to hub or file
func (fm *Frontman) RunOnce(inputFilePath string, outputFile *os.File, interrupt chan struct{}, resultsChan *chan Result) error {

	var err error

	checks, err := fm.fetchInputChecks(inputFilePath)
	fm.handleHubError(err)

	fm.processInput(checks, true, resultsChan)

	logrus.Debugf("RunOnce")
	close(*resultsChan)

	if outputFile != nil {
		logrus.Debugf("sendResultsChanToFile")
		err = fm.sendResultsChanToFile(resultsChan, outputFile)
	} else {
		err = fm.sendResultsChanToHub(resultsChan)
	}

	return nil
}

func (fm *Frontman) handleHubError(err error) {
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
		delay := secToDuration(fm.Config.Sleep)
		logrus.Debugf("handleHubError sleeping for %v", delay)
		time.Sleep(delay)
	case err != nil && err == ErrorHubTooManyRequests:
		logrus.Warnln(err)
		// for error code 429, wait 10 seconds and try again
		time.Sleep(10 * time.Second)
	case err != nil:
		logrus.Error(err)
	default:
	}
}

func (input *Input) asChecks() []Check {
	checks := []Check{}
	for _, c := range input.ServiceChecks {
		checks = append(checks, c)
	}
	for _, c := range input.WebChecks {
		checks = append(checks, c)
	}
	for _, c := range input.SNMPChecks {
		checks = append(checks, c)
	}
	return checks
}

// fetchInputChecks reads checks from a json file or the hub
func (fm *Frontman) fetchInputChecks(inputFilePath string) ([]Check, error) {
	var input *Input
	var err error

	if inputFilePath != "" {
		input, err = InputFromFile(inputFilePath)
		if err != nil {
			return nil, fmt.Errorf("InputFromFile(%s) error: %s", inputFilePath, err.Error())
		}
		return input.asChecks(), nil
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

	checks := input.asChecks()
	diag := fmt.Sprintf("fetchInputChecks read %v checks from hub", len(checks))
	if len(checks) > 0 {
		logrus.Info(diag)
	} else {
		logrus.Debug(diag)
	}

	return checks, nil
}

// appends new checks with unique UUID to input Check queue
func addUniqueChecks(input []Check, new []Check) []Check {
	filtered := input
	for _, c := range new {
		if !hasCheck(input, c.uniqueID()) {
			filtered = append(filtered, c)
		} else {
			logrus.Infof("Skipping request for check %v. Check is in queue.", c.uniqueID())
		}
	}
	logrus.Debugf("addUniqueChecks: queue size %v, new %v, new queue size %v", len(input), len(new), len(filtered))
	return filtered
}

func hasCheck(s []Check, uuid string) bool {
	for _, v := range s {
		if v.uniqueID() == uuid {
			return true
		}
	}
	return false
}

// local is false if check originated from a remote node
func (fm *Frontman) processInputContinuous(inputFilePath string, local bool, interrupt chan struct{}, resultsChan *chan Result) {

	lastFetch := time.Unix(0, 0)
	interval := secToDuration(fm.Config.Sleep)

	var err error
	var checks []Check
	var newChecks []Check
	var ipc inProgressChecks

	for {
		duration := time.Since(lastFetch)
		if duration >= interval {
			newChecks, err = fm.fetchInputChecks(inputFilePath)
			lastFetch = time.Now()
			fm.handleHubError(err)
			checks = addUniqueChecks(checks, newChecks)
		}

		if len(checks) > 0 {
			// take oldest check from queue
			// XXX TODO: instead, find a check that is not already in progress and poll it. need another "in-progress queue"
			currentCheck := checks[0]
			checks = checks[1:]
			ipc.add(currentCheck.uniqueID())

			go func(check Check, results *chan Result, inProgress *inProgressChecks) {
				res, _ := fm.runCheck(check, local)
				inProgress.remove(check.uniqueID())
				*results <- *res
			}(currentCheck, resultsChan, &ipc)
		}
		select {
		case <-interrupt:
			close(*resultsChan)
			return
		default:
		}
	}
}

// processInput processes the whole list of checks in input
// local is false if check originated from a remote node
func (fm *Frontman) processInput(checks []Check, local bool, resultsChan *chan Result) {
	startedAt := time.Now()

	succeed := fm.runChecks(checks, resultsChan, local)

	totChecks := len(checks)
	fm.Stats.ChecksPerformedTotal += uint64(totChecks)
	logrus.Infof("%d/%d checks succeed in %.1f sec", succeed, totChecks, time.Since(startedAt).Seconds())
}

// runs all checks in checkList and sends results to resultsChan
func (fm *Frontman) runChecks(checkList []Check, resultsChan *chan Result, local bool) int {
	wg := &sync.WaitGroup{}

	succeed := 0
	for _, check := range checkList {
		wg.Add(1)
		go func(wg *sync.WaitGroup, check Check, resultsChan *chan Result) {
			defer wg.Done()

			res, err := fm.runCheck(check, local)
			if err == nil {
				succeed++
			}

			*resultsChan <- *res
		}(wg, check, resultsChan)
	}

	wg.Wait()

	return succeed
}

func (fm *Frontman) runCheck(check Check, local bool) (*Result, error) {
	res, err := check.run(fm)

	if err != nil {
		recovered := false
		if fm.Config.FailureConfirmation > 0 {
			logrus.Debugf("runChecks failed, retrying up to %d times: %s: %s", fm.Config.FailureConfirmation, check.uniqueID(), err.Error())

			for i := 1; i <= fm.Config.FailureConfirmation; i++ {
				time.Sleep(time.Duration(fm.Config.FailureConfirmationDelay*1000) * time.Millisecond)
				logrus.Debugf("Retry %d for failed check %s", i, check.uniqueID())
				res, err = check.run(fm)
				if err == nil {
					recovered = true
					break
				}
			}
		}
		if !recovered {
			res.Message = err.Error()
		}
		if !recovered && local {
			fm.askNodes(check, res)
		}

		if !recovered {
			logrus.Debugf("runChecks: %s: %s", check.uniqueID(), err.Error())
		}
	}
	return res, err
}
