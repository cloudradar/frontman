package frontman

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (fm *Frontman) postResultsToHub(results []Result) error {
	if len(results) == 0 {
		return nil
	}

	fm.offlineResultsLock.Lock()
	defer fm.offlineResultsLock.Unlock()
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

		fm.offlineResultsBuffer = results
		b, err = json.Marshal(Results{
			Results: fm.offlineResultsBuffer,
		})
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

	logrus.Infof("Sent %d results to Hub.. Status %d", len(fm.offlineResultsBuffer), resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		logrus.Debugf("postResultsToHub failed with %v", resp.Status)
		return ErrorHubGeneral{resp.StatusCode, resp.Status}
	}

	// in case of successful POST, we reset the offline buffer
	fm.offlineResultsBuffer = []Result{}

	// Update frontman statistics
	fm.statsLock.Lock()
	fm.stats.BytesSentToHubTotal += uint64(bodyLength)
	fm.statsLock.Unlock()

	return nil
}

func (fm *Frontman) sendResultsChanToFile(outputFile *os.File) error {
	var results []Result
	var jsonEncoder = json.NewEncoder(outputFile)
	for res := range fm.resultsChan {
		results = append(results, res)
	}

	return jsonEncoder.Encode(results)
}

// posts results to hub, used by RunOnce
func (fm *Frontman) sendResultsChanToHub() error {
	var results []Result
	logrus.Infof("sendResultsChanToHub collecting results. len %v", len(fm.resultsChan))

	for res := range fm.resultsChan {
		results = append(results, res)
	}
	logrus.Infof("sendResultsChanToHub posting. len %v", len(results))
	err := fm.postResultsToHub(results)
	if err != nil {
		return fmt.Errorf("postResultsToHub: %s", err.Error())
	}

	fm.statsLock.Lock()
	fm.stats.CheckResultsSentToHub += uint64(len(results))
	fm.statsLock.Unlock()

	return nil
}

func (fm *Frontman) writeQueueStatsContinuous() {
	writeQueueStatsInterval := time.Millisecond * 200

	for {
		select {
		case <-fm.InterruptChan:
			logrus.Infof("writeQueueStatsContinuous interrupt caught, returning")
			return
		case <-time.After(writeQueueStatsInterval):
			fm.writeQueueStats()
		}
	}
}

func (fm *Frontman) pollResultsChan() {

	// chan polling is blocking until closed
	for res := range fm.resultsChan {
		fm.resultsLock.Lock()
		fm.results = append(fm.results, res)
		fm.resultsLock.Unlock()
	}

	logrus.Debugf("pollResultsChan resultsChan closed, returning")
}

// sends results to hub continuously
func (fm *Frontman) sendResultsChanToHubQueue() {

	sendInterval := secToDuration(float64(fm.Config.SenderInterval))
	sendResults := []Result{}
	lastSentToHub := time.Unix(0, 0)

	for {
		if time.Since(lastSentToHub) >= sendInterval {
			lastSentToHub = time.Now()
			fm.resultsLock.Lock()
			if len(fm.results) >= fm.Config.SenderBatchSize {
				sendResults = fm.results[0:fm.Config.SenderBatchSize]
				fm.results = fm.results[fm.Config.SenderBatchSize:]
			} else {
				sendResults = fm.results
				fm.results = nil
			}
			fm.resultsLock.Unlock()

			if len(sendResults) > 0 {
				logrus.Infof("sendResultsChanToHubQueue: sending %v results", len(sendResults))
				fm.TerminateQueue.Add(1)
				go func(r []Result) {
					defer fm.TerminateQueue.Done()

					err := fm.postResultsToHub(r)

					fm.statsLock.Lock()
					fm.stats.CheckResultsSentToHub += uint64(len(r))
					fm.statsLock.Unlock()

					if err != nil {
						switch err.(type) {
						case ErrorHubGeneral:
							// If the hub doesn't respond with 2XX, the results remain in the queue.
							fm.resultsLock.Lock()
							fm.results = append(fm.results, r...)
							fm.resultsLock.Unlock()
						}
						logrus.Errorf("postResultsToHub error: %s", err.Error())
					}
				}(sendResults)
			} else {
				logrus.Infof("sendResultsChanToHubQueue: nothing to do. outgoing queue empty.")
			}
		}

		select {
		case <-fm.InterruptChan:
			fm.resultsLock.RLock()
			logrus.Infof("sendResultsChanToHubQueue interrupt caught, posting last %d results", len(fm.results))
			if err := fm.postResultsToHub(fm.results); err != nil {
				logrus.Error(err)
			}
			fm.resultsLock.RUnlock()
			return
		case <-time.After(250 * time.Millisecond):
			continue
		}
	}
}

func (fm *Frontman) writeQueueStats() {
	if fm.Config.QueueStatsFile == "" {
		return
	}

	fm.ipc.mutex.RLock()
	ipcLen := len(fm.ipc.uuids)
	fm.ipc.mutex.RUnlock()

	fm.checksLock.RLock()
	checksLen := len(fm.checks)
	fm.checksLock.RUnlock()

	fm.resultsLock.RLock()
	resultsLen := len(fm.results)
	fm.resultsLock.RUnlock()

	data, err := json.Marshal(map[string]int{
		"checks_queue":       checksLen,
		"checks_in_progress": ipcLen,
		"results_queue":      resultsLen,
		"ts":                 int(time.Now().UnixNano())})

	if err != nil {
		logrus.Error("writeQueueStats Marshal", err)
		return
	}

	go func(b []byte) {
		f, err := os.Create(fm.Config.QueueStatsFile)
		if err != nil {
			logrus.Error("writeQueueStats Create", err)
			return
		}
		defer f.Close()
		_, err = f.Write(b)
		if err != nil {
			logrus.Error("writeQueueStats Write", err)
		}
	}(data)
}
