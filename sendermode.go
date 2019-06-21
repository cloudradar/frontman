package frontman

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (fm *Frontman) PostResultsToHub(results []Result) error {
	fm.initHubClient()
	for _, res := range results {
		if s, ok := res.Message.(string); ok {
			if strings.Contains(s, "too many open files") {
				// NOTE: work-around for too many open files. Remove this when resolved
				return fmt.Errorf("skipping post to hub because of %v", res.Message)
			}
		}
	}

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

	logrus.Debugf("Sent %d results to Hub.. Status %d", len(results), resp.StatusCode)

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

		logrus.Debugf("SenderModeInterval: send %d results", len(results))
		err := fm.PostResultsToHub(results)
		if err != nil {
			err = fmt.Errorf("PostResultsToHub error: %s", err.Error())
		}

		if shouldReturn {
			return err
		}

		if err != nil {
			logrus.Error(err)
		}
	}
}
