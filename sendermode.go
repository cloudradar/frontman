package frontman

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (fm *Frontman) postResultsToHub(results []Result) error {
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
		logrus.Errorf("hub_max_offline_buffer_bytes(%d bytes) exceed with %d results. Flushing the buffer...",
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
		if _, err := zw.Write(b); err != nil {
			_ = zw.Close()
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}

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

	logrus.Infof("Sent %d results to Hub.. Status %d", len(results), resp.StatusCode)

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

// used when sender_mode == "wait" (post results to hub after each round)
func (fm *Frontman) sendResultsChanToHub(resultsChan chan Result) error {
	var results []Result
	for res := range resultsChan {
		results = append(results, res)
	}
	err := fm.postResultsToHub(results)
	if err != nil {
		return fmt.Errorf("postResultsToHub: %s", err.Error())
	}

	fm.Stats.CheckResultsSentToHub += uint64(len(results))

	fm.offlineResultsBuffer = []Result{}
	return nil
}

// used when sender_mode == "interval" (post results to hub by fixed interval)
func (fm *Frontman) sendResultsChanToHubWithInterval(resultsChan chan Result) error {
	started := time.Now()
	delay := secToDuration(fm.Config.SenderModeInterval)
	sendResultsTicker := time.NewTicker(delay)
	defer sendResultsTicker.Stop()

	var results []Result
	shouldReturn := false

	for {
		select {
		case res, ok := <-resultsChan:
			if !ok {
				// chan was closed, no more results left
				shouldReturn = true
				break
			}

			results = append(results, res)
			// skip postResultsToHub
			continue
		case <-sendResultsTicker.C:
			break
		}

		logrus.Debugf("SenderModeInterval: send %d results", len(results))
		err := fm.postResultsToHub(results)
		if err != nil {
			err = fmt.Errorf("postResultsToHub error: %s", err.Error())
		}

		// sleep until interval has passed in full
		timeLeft := delay - time.Since(started)
		if timeLeft > 0 {
			time.Sleep(timeLeft)
		}

		if shouldReturn {
			return err
		}

		if err != nil {
			logrus.Error(err)
		}
	}
}

// used when sender_mode == "queue" (post results to hub continiously)
func (fm *Frontman) sendResultsChanToHubQueue(resultsChan chan Result) error {

	interval := secToDuration(float64(fm.Config.QueueSenderRequestInterval))

	results := []Result{}
	sendResults := []Result{}
	shouldReturn := false

	for {
		select {
		case res, ok := <-resultsChan:
			if !ok {
				// chan was closed, no more results left
				logrus.Debug("chan was closed, no more results left")
				shouldReturn = true
				break
			}

			results = append(results, res)
			if len(results) < fm.Config.QueueSenderBatchSize && !shouldReturn {
				// wait for enough results before post
				continue
			}
		}

		sendResults = results
		logrus.Debugf("SenderModeQueue: send %d results", len(sendResults))
		results = nil

		var err error
		if len(sendResults) > 0 {
			err = fm.postResultsToHub(sendResults)
			if err != nil {
				err = fmt.Errorf("postResultsToHub error: %s", err.Error())
			}
		}
		logrus.Infof("Results in channel: %d", len(resultsChan))

		if shouldReturn {
			return err
		}

		if err != nil {
			logrus.Error(err)
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		logrus.Debugf("SenderModeQueue: sleep for %v. Alloc = %v, TotalAlloc = %v, Sys = %v, NumGC = %v", interval, m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC)

		time.Sleep(interval)
	}
}
