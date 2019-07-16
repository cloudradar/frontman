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

func (fm *Frontman) askNeighbors(data []byte) {
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

	if len(responses) > 0 {
		bestDuration := 999.

		// select the fastest response, fall back to first result if we fail
		responseID := 0
		for currID, resp := range responses {

			var selected interface{}

			if err := json.Unmarshal([]byte(resp), &selected); err != nil {
				logrus.Error(err)
				continue
			}

			// recognize response type and check relevant values
			if l1, ok := selected.(map[string]interface{}); ok {
				if l2, ok := l1["messages"].(map[string]interface{}); ok {
					if duration, ok := l2["net.icmp.ping.roundTripTime_s"].(float64); ok {
						if duration < bestDuration {
							logrus.Debug("neighbor: selected response ", currID)
							responseID = currID
							bestDuration = duration
						}
					}
				}
			}
		}

		var result Result

		if err := json.Unmarshal([]byte(responses[responseID]), &result); err != nil {
			logrus.Error(err)
			return
		}
		// spew.Dump(result)

		// attach new message to result
		if len(responses) != len(fm.Config.Neighbors) {
			failedNeighbors := len(fm.Config.Neighbors) - len(responses)
			result.Message = fmt.Sprintf("Check failed locally and on %d neigbors but succeded on %s", failedNeighbors, strings.Join(succeededNeighbors, ", "))
		} else {
			result.Message = "Check failed locally but succeded on all neighbors"
		}

		result.GroupMeasurements = responses

		// spew.Dump(result)

		err := fm.postResultsToHub([]Result{result})
		if err != nil {
			logrus.Errorf("askNeighbors postResultsToHub error: %s", err.Error())
		}

	} else {
		logrus.Errorf("askNeighbors recieved no successful results")
	}
}
