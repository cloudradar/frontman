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

func (fm *Frontman) askNodes(data []byte, res *Result) {
	var nodeResults []string
	var succeededNodes []string
	var failedNodes []string

	if len(fm.Config.Nodes) < 1 {
		return
	}

	for _, node := range fm.Config.Nodes {
		url, err := url.Parse(node.URL)
		if err != nil {
			logrus.Warnf("Invalid node url in config: '%s': %s", node.URL, err.Error())
			continue
		}
		url.Path = path.Join(url.Path, "check")
		logrus.Debug("asking node ", node.URL)

		client := &http.Client{}
		if !node.VerifySSL {
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		req, _ := http.NewRequest("POST", url.String(), bytes.NewBuffer(data))
		req.SetBasicAuth(node.Username, node.Password)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			logrus.Warnf("Failed to ask node: %s", err.Error())
		} else {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				nodeResults = append(nodeResults, string(body))
			}
		}
	}

	if len(nodeResults) == 0 {
		logrus.Errorf("askNodes recieved no successful results")
		return
	}

	bestDuration := 999.

	// select the fastest result, fall back to first result if we fail
	resultID := 0
	for currID, resp := range nodeResults {

		var selected []interface{}
		if err := json.Unmarshal([]byte(resp), &selected); err != nil {
			logrus.Error(err)
			continue
		}

		// recognize response type and check relevant values
		if l1, ok := selected[0].(map[string]interface{}); ok {

			nodeName := ""
			if n, ok := l1["node"].(string); ok {
				nodeName = n
			}

			if l2, ok := l1["measurements"].(map[string]interface{}); ok {

				successKey := ""
				for key := range l2 {
					lastPeriod := strings.LastIndex(key, ".")
					if lastPeriod == -1 {
						continue
					}
					switch key[lastPeriod+1:] {
					case "success":
						successKey = key
					}
				}
				if successKey == "" {
					continue
				}

				if success, ok := l2[successKey].(float64); ok {
					if int(success) == 1 {
						succeededNodes = append(succeededNodes, nodeName)
					} else {
						failedNodes = append(failedNodes, nodeName)
						continue
					}
				}

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
						resultID = currID
						bestDuration = duration
					}
				}
			}
		}
	}

	var fastestResult []Result
	if err := json.Unmarshal([]byte(nodeResults[resultID]), &fastestResult); err != nil {
		logrus.Error(err)
	}
	if len(fastestResult) < 1 {
		logrus.Warning("no results gathered from node")
		return
	}

	locallMeasurement := *res

	// make the fastest node measurement the main result
	*res = fastestResult[0]

	// attach new message to result
	if len(nodeResults) != len(fm.Config.Nodes) {
		(*res).Message = fmt.Sprintf("Check failed on %s and %s but succeded on %s", fm.Config.NodeName, strings.Join(failedNodes, ", "), strings.Join(succeededNodes, ", "))
	} else {
		(*res).Message = fmt.Sprintf("Check failed on %s but succeded on %s", fm.Config.NodeName, strings.Join(succeededNodes, ", "))
	}

	// combine the other measurments with the failing measurement
	for idx := range nodeResults {
		if idx == resultID {
			continue
		}

		var result []Result
		if err := json.Unmarshal([]byte(nodeResults[idx]), &result); err != nil {
			logrus.Error(err)
		}

		var out []map[string]interface{}
		inrec, _ := json.Marshal(result)
		json.Unmarshal(inrec, &out)

		(*res).NodeMeasurements = append((*res).NodeMeasurements, out...)
	}

	var locallMeasurementInterface map[string]interface{}
	tmp, _ := json.Marshal(locallMeasurement)
	json.Unmarshal(tmp, &locallMeasurementInterface)

	(*res).NodeMeasurements = append((*res).NodeMeasurements, locallMeasurementInterface)
}
