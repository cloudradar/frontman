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
	"time"

	"github.com/sirupsen/logrus"
)

// checks if given node recently failed
func (fm *Frontman) nodeRecentlyFailed(node *Node) bool {
	limit := time.Second * time.Duration(fm.Config.Node.NodeCacheErrors)

	if when, ok := fm.failedNodes[node.URL]; ok {
		if time.Since(when) < limit {
			logrus.Debugf("skipping recently failed node %s", node.URL)
			return true
		}
	}

	return false
}

// marks a node as temporarily failing
func (fm *Frontman) markNodeFailure(node *Node) {
	fm.failedNodes[node.URL] = time.Now()
	fm.failedNodeCache[node.URL] = *node
}

// returns the most recent cached node failure
func (fm *Frontman) getCachedNodeFailure(node *Node) *Node {
	if n, ok := fm.failedNodeCache[node.URL]; ok {
		return &n
	}
	return nil
}

// asking other nodes to try a failed check
func (fm *Frontman) askNodes(check Check, res *Result) {

	var data []byte

	if len(fm.Config.Nodes) < 1 {
		return
	}

	if c, ok := check.(ServiceCheck); ok {
		if c.Check.Protocol == "ssl" {
			// ssl checks are excluded from "ask node" feature
			return
		}
		req := &Input{ServiceChecks: []ServiceCheck{c}}
		data, _ = json.Marshal(req)
	}
	if c, ok := check.(WebCheck); ok {
		req := &Input{WebChecks: []WebCheck{c}}
		data, _ = json.Marshal(req)
	}
	if c, ok := check.(SNMPCheck); ok {
		req := &Input{SNMPChecks: []SNMPCheck{c}}
		data, _ = json.Marshal(req)
	}

	var nodeResults []string
	var succeededNodes []string
	var failedNodes []string
	failedNodeMessage := make(map[string]string)

	for _, node := range fm.Config.Nodes {
		if fm.nodeRecentlyFailed(&node) {
			logrus.Warnf("Skipping recently failed node %s", node.URL)
			failedNodes = append(failedNodes, node.URL)
			if failure := fm.getCachedNodeFailure(&node); failure != nil {
				failureText, _ := json.Marshal(failure)
				nodeResults = append(nodeResults, string(failureText))
			}
			continue
		}

		url, err := url.Parse(node.URL)
		if err != nil {
			logrus.Warnf("Invalid node url in config: '%s': %s", node.URL, err.Error())
			continue
		}
		url.Path = path.Join(url.Path, "check")
		logrus.Debug("asking node ", node.URL)

		client := &http.Client{
			Timeout: time.Duration(fm.Config.Node.NodeTimeout) * time.Second,
		}
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
			logrus.Errorf("askNodes failed: %s", err.Error())
			fm.markNodeFailure(&node)
		} else {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				nodeResults = append(nodeResults, string(body))
			} else {
				logrus.Errorf("askNodes recieved HTTP %v from %s", resp.StatusCode, node.URL)
				fm.markNodeFailure(&node)
			}
		}
	}

	if len(nodeResults) == 0 {
		// all nodes failed, use original measure
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

			nodeMessage := ""
			if n, ok := l1["message"].(string); ok {
				nodeMessage = n
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
						failedNodeMessage[nodeName] = nodeMessage
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

	// append all node messages to Message response
	msg := fm.Config.NodeName + ": " + res.Message.(string) + "\n"
	for _, v := range failedNodes {
		msg += fmt.Sprintf("%s: %s\n", v, failedNodeMessage[v])
	}
	for _, v := range succeededNodes {
		msg += fmt.Sprintf("%s: check succeeded\n", v)
	}

	(*res).Message = msg

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
