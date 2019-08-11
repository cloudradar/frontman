package frontman

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
)

func (fm *Frontman) askNeighbors(data []byte, res *Result) {
	var responses []string
	var succeededNeighbors []string

	for _, neighbor := range fm.Config.Neighbors {
		url, err := url.Parse(neighbor.URL)
		if err != nil {
			logrus.Warnf("Invalid neighbor url in config: '%s': %s", neighbor.URL, err.Error())
			continue
		}
		url.Path = path.Join(url.Path, "check")
		logrus.Debug("asking neighbor ", neighbor.Name)

		client := &http.Client{}
		if !neighbor.VerifySSL {
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		req, _ := http.NewRequest("POST", url.String(), bytes.NewBuffer(data))
		req.SetBasicAuth(neighbor.Username, neighbor.Password)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			logrus.Warnf("Failed to ask neighbor: %s", err.Error())
		} else {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				responses = append(responses, string(body))
				succeededNeighbors = append(succeededNeighbors, neighbor.Name)
			}
		}
	}

	if len(responses) == 0 {
		logrus.Errorf("askNeighbors recieved no successful results")
		return
	}

	bestDuration := 999.

	// select the fastest response, fall back to first result if we fail
	responseID := 0
	for currID, resp := range responses {

		var selected []interface{}
		if err := json.Unmarshal([]byte(resp), &selected); err != nil {
			logrus.Error(err)
			continue
		}

		// recognize response type and check relevant values
		if l1, ok := selected[0].(map[string]interface{}); ok {
			if l2, ok := l1["measurements"].(map[string]interface{}); ok {

				useKey := ""
				for key := range l2 {
					lastPeriod := strings.LastIndex(key, ".")
					if lastPeriod == -1 {
						continue
					}
					switch key[lastPeriod+1:] {
					case "roundTripTime_s", "totalTimeSpent_s", "connectTime_s":
						useKey = key
					}
				}
				if useKey == "" {
					continue
				}
				if duration, ok := l2[useKey].(float64); ok {
					if duration < bestDuration {
						logrus.Debug("neighbor: selected response ", currID)
						responseID = currID
						bestDuration = duration
					}
				}
			}
		}
	}

	// attach new message to result
	if len(responses) != len(fm.Config.Neighbors) {
		failedNeighbors := len(fm.Config.Neighbors) - len(responses)
		res.Message = fmt.Sprintf("Check failed locally and on %d neigbors but succeded on %s", failedNeighbors, strings.Join(succeededNeighbors, ", "))
	} else {
		res.Message = "Check failed locally but succeded on all neighbors"
	}

	res.GroupMeasurements = responses[responseID]
}
