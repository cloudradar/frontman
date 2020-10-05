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

func (fm *Frontman) sendResultsChanToFile(resultsChan *chan Result, outputFile *os.File) error {
	var results []Result
	var jsonEncoder = json.NewEncoder(outputFile)
	for res := range *resultsChan {
		results = append(results, res)
	}

	return jsonEncoder.Encode(results)
}

// posts results to hub
func (fm *Frontman) sendResultsChanToHub(resultsChan *chan Result) error {
	var results []Result
	logrus.Infof("sendResultsChanToHub collecting results. len %v", len(*resultsChan))

	for res := range *resultsChan {
		results = append(results, res)
	}
	logrus.Infof("sendResultsChanToHub posting. len %v", len(results))
	err := fm.postResultsToHub(results)
	if err != nil {
		return fmt.Errorf("postResultsToHub: %s", err.Error())
	}

	fm.Stats.CheckResultsSentToHub += uint64(len(results))

	fm.offlineResultsBuffer = []Result{}
	return nil
}

// sends results to hub continuously
func (fm *Frontman) sendResultsChanToHubQueue(resultsChan *chan Result) error {

	interval := secToDuration(float64(fm.Config.SenderInterval))

	results := []Result{}
	sendResults := []Result{}
	shouldReturn := false

	lastSentToHub := time.Unix(0, 0)

	fm.TerminateQueue.Add(1)

	for {
		select {
		case res, ok := <-*resultsChan:
			if !ok {
				// chan was closed, no more results left
				shouldReturn = true
			} else {
				results = append(results, res)
				if len(results) < fm.Config.SenderBatchSize && len(*resultsChan) > 0 {
					continue
				}
			}
		}

		duration := time.Since(lastSentToHub)
		if duration >= interval {

			if len(results) >= fm.Config.SenderBatchSize {
				sendResults = results[0:fm.Config.SenderBatchSize]
				results = results[fm.Config.SenderBatchSize:]
			} else {
				sendResults = results
				results = nil
			}

			if len(sendResults) > 0 {
				logrus.Infof("Send %d results to hub, %d results in queue", len(sendResults), len(results))
				lastSentToHub = time.Now()
				go func(r []Result) {
					err := fm.postResultsToHub(r)
					if err != nil {
						logrus.Errorf("postResultsToHub error: %s", err.Error())
					}

					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					logrus.Debugf("Sender queue: Alloc = %v, TotalAlloc = %v, Sys = %v, NumGC = %v", m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC)
				}(sendResults)
			} else {
				logrus.Debugf("Sender queue: nothing to do. outgoing queue empty.")
			}
		}

		if shouldReturn && len(results) == 0 {
			fm.TerminateQueue.Done()
			return nil
		}
	}
}
