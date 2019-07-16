package frontman

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
)

func (fm *Frontman) askNeighbors(data []byte) {
	var responses []string

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
			}
		}
	}

	if len(responses) > 0 {
		spew.Dump(responses)

		// XXX create a new result message with fastest result + group_measurements with all responses
		// XXX attach new message to result: "message": "Check failed locally and on 2 neigbors but succeded on Frontman EU"

		responseID := 0 // XXX select the fastest response

		var selected interface{}

		if err := json.Unmarshal([]byte(responses[responseID]), &selected); err != nil {
			logrus.Error(err)
			return
		}
		spew.Dump(selected)

		// create results
		var result Result

		if chk, ok := selected.(Result); ok {
			result.CheckUUID = chk.CheckUUID
			result.Timestamp = chk.Timestamp
			result.CheckType = chk.CheckType
			result.Check = chk.Check
			result.Measurements = chk.Measurements
			result.Message = "Check failed locally and on X neigbors but succeded on XXXXX"
		}

		result.GroupMeasurements = responses

		err := fm.postResultsToHub([]Result{result})
		if err != nil {
			logrus.Errorf("askNeighbors postResultsToHub error: %s", err.Error())
		}

	} else {
		logrus.Errorf("askNeighbors recieved no successful results")
	}
}
