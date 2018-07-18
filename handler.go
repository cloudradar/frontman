package frontman

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func InputFromFile(filename string) (*Input, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("parseInputFromFile: '%s' failed to read the file: %s", filename, err.Error())
	}

	var r Input
	err = json.Unmarshal(b, &r)

	if err != nil {
		return nil, fmt.Errorf("parseInputFromFile: '%s' JSON unmarshal error: %s", filename, err.Error())
	}
	return &r, nil
}

func InputFromHub(hubURL, hubLogin, hubPassword string) (*Input, error) {
	client := http.Client{Timeout: time.Second * 30}

	var i Input
	r, err := http.NewRequest("GET", hubURL, nil)
	if err != nil {
		return nil, err
	}

	if hubLogin != "" {
		r.SetBasicAuth(hubLogin, hubPassword)
	}

	resp, err := client.Do(r)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.New(resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(&i)

	if err != nil {
		return nil, err
	}

	return &i, nil
}

func (fm *Frontman) PostResultsToHub(results []Result) error {
	client := http.Client{Timeout: time.Second * 30}
	b, err := json.Marshal(Results{results})
	if err != nil {
		return err
	}

	r, err := http.NewRequest("POST", fm.HubURL, bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	if fm.HubUser != "" {
		r.SetBasicAuth(fm.HubUser, fm.HubPassword)
	}

	resp, err := client.Do(r)

	if err != nil {
		return err
	}

	log.Debugf("Sent to HUB.. Status %d", resp.StatusCode)

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return errors.New(resp.Status)
	}

	return nil
}

func (fm *Frontman) Run(input *Input, outputFile *os.File, interrupt chan struct{}) {

	var jsonEncoder *json.Encoder

	if outputFile != nil {
		jsonEncoder = json.NewEncoder(outputFile)
	}

	sendResultsTicker := time.Tick(secToDuration(fm.SenderModeInterval))

	outputLock := sync.Mutex{}

	var results []Result
	for true {
		// in case HUB server will hang on response we will need a buffer to continue perform checks
		resultsChan := make(chan Result, 100)

		fm.onceChan(input, resultsChan)
		if outputFile != nil {
			for res := range resultsChan {
				outputLock.Lock()
				jsonEncoder.Encode(res)
				outputLock.Unlock()
			}
		} else if fm.SenderMode == SenderModeInterval {
		modeIntervalLoop:
			for {
				select {
				case res, ok := <-resultsChan:
					if !ok {
						// chan was closed
						break modeIntervalLoop
					}
					results = append(results, res)
				case <-sendResultsTicker:
					log.Debugf("SenderModeInterval: send %d results", len(results))
					err := fm.PostResultsToHub(results)
					if err != nil {
						log.Errorf("PostResultsToHub: %s", err.Error())
					} else {
						results = []Result{}
					}
				case <-interrupt:
					return
				default:
					continue
				}
			}
		} else if fm.SenderMode == SenderModeWait {
			for res := range resultsChan {
				results = append(results, res)
			}
			err := fm.PostResultsToHub(results)
			if err != nil {
				log.Errorf("PostResultsToHub: %s", err.Error())
			} else {
				results = []Result{}
			}
		}

		select {
		case <-interrupt:
			return
		default:
			continue
		}
	}
}

func (fm *Frontman) Once(input *Input, outputFile io.Writer) {
	jsonEncoder := json.NewEncoder(outputFile)

	resultsChan := make(chan Result)

	go fm.onceChan(input, resultsChan)

	var results []Result
	for res := range resultsChan {
		results = append(results, res)
	}

	jsonEncoder.Encode(results)
}

func (fm *Frontman) onceChan(input *Input, resultsChan chan<- Result) {
	wg := sync.WaitGroup{}

	startedAt := time.Now()
	succeed := 0

	for _, check := range input.ServiceChecks {
		wg.Add(1)
		go func(check ServiceCheck) {
			res := Result{
				CheckType: "serviceCheck",
				CheckKey:  string(check.Key),
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}
			res.Data.Check = check.Data

			defer wg.Done()
			ipaddr, err := net.ResolveIPAddr("ip", check.Data.Connect)
			if err != nil {
				res.Data.Message = err.Error()
			} else {

				switch check.Key {
				case CheckTypeICMPPing:
					res.Data.Measurements, res.FinalResult, res.Data.Message = fm.runPing(ipaddr)
				case CheckTypeTCP:
					port, err := check.Data.Port.Int64()

					if err != nil {
						res.Data.Message = "Unknown port"
					} else {
						res.Data.Measurements, res.FinalResult, res.Data.Message = fm.runTCPCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)})
					}
				default:
					res.Data.Message = "Unknown checkKey"
				}
			}

			if res.FinalResult == 1 {
				succeed++
			}

			resultsChan <- res
		}(check)
	}

	wg.Wait()
	close(resultsChan)

	log.Infof("%d/%d checks succeed in %.1f sec", succeed, len(input.ServiceChecks), time.Since(startedAt).Seconds())
	time.Sleep(secToDuration(fm.Sleep))
}
