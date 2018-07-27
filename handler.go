package frontman

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
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

func (fm *Frontman) Run(input *Input, outputFile *os.File, interrupt chan struct{}, once bool) {

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

		go fm.onceChan(input, resultsChan)
		if outputFile != nil && once {
			var results []Result
			for res := range resultsChan {
				results = append(results, res)
			}

			jsonEncoder.Encode(results)
			return
		} else if outputFile != nil {
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
					if once {
						return
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
			if once {
				return
			}
		}

		select {
		case <-interrupt:
			return
		default:
			continue
		}

		time.Sleep(secToDuration(fm.Sleep))
	}
}

func (fm *Frontman) onceChan(input *Input, resultsChan chan<- Result) {
	wg := sync.WaitGroup{}

	startedAt := time.Now()
	succeed := 0

	for _, check := range input.ServiceChecks {
		wg.Add(1)
		go func(check ServiceCheck) {
			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				log.Errorf("serviceCheck: missing checkUuid key")
				return
			}

			res := Result{
				CheckType: "serviceCheck",
				CheckKey:  string(check.Key),
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Data.Check = check.Data

			if check.Data.Connect == "" {
				log.Errorf("serviceCheck: missing data.connect key")
				res.Data.Message = "Missing data.connect key"
			} else {

				defer wg.Done()
				ipaddr, err := net.ResolveIPAddr("ip", check.Data.Connect)
				if err != nil {
					res.Data.Message = err.Error()
					log.Debugf("serviceCheck: ResolveIPAddr error: %s", err.Error())
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
					case "":
						log.Errorf("serviceCheck: missing checkKey")
						res.Data.Message = "Missing checkKey"
					default:
						log.Errorf("serviceCheck: unknown checkKey: '%s'", check.Key)
						res.Data.Message = "Unknown checkKey"
					}
				}
			}

			if res.FinalResult == 1 {
				succeed++
			}

			resultsChan <- res
		}(check)
	}

	for _, check := range input.WebChecks {
		wg.Add(1)
		go func(check WebCheck) {
			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				log.Errorf("webCheck: missing checkUuid key")
				return
			}

			res := Result{
				CheckType: "webCheck",
				CheckKey:  string(check.Key),
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Data.Check = check

			if check.Data.Method == "" {
				log.Errorf("webCheck: missing data.method key")
				res.Data.Message = "Missing data.method key"
			} else if check.Data.URL == "" {
				log.Errorf("webCheck: missing data.url key")
				res.Data.Message = "Missing data.url key"
			} else {
				defer wg.Done()
				res.Data.Measurements, res.FinalResult, res.Data.Message = fm.runWebCheck(check.Data)
				if res.Data.Message != nil {
					log.Debugf("webCheck: %s: %s", check.UUID, res.Data.Message)
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

	log.Infof("%d/%d checks succeed in %.1f sec", succeed, len(input.ServiceChecks)+len(input.WebChecks), time.Since(startedAt).Seconds())
}
