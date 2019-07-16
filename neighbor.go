package frontman

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
)

func (fm *Frontman) askNeighbors(data []byte) {
	var responses []http.Response

	for _, neighbor := range fm.Config.Neighbors {
		logrus.Debug("asking neighbor", neighbor.Name)
		url, err := url.Parse(neighbor.URL)
		if err != nil {
			logrus.Warnf("Invalid neighbor url in config: '%s': %s", neighbor.URL, err.Error())
			continue
		}
		url.Path = path.Join(url.Path, "check")
		logrus.Debug("connecting to neighbor ", url.String())

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

			fmt.Println("response Status:", resp.Status)
			// fmt.Println("response Headers:", resp.Header)
			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Println("response Body:", string(body))

			// responses = append(responses, *res)
		}
	}

	if len(responses) > 0 {
		// XXX pick "fastest result" and send it back
		spew.Dump(responses)

		// XXX create a new result message with fastest result + group_measurements with all responses
		// XXX attach new messagew to result: "message": "Check failed locally and on 2 neigbors but succeded on Frontman EU"
	}
}
