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

			err := jsonEncoder.Encode(results)
			if err != nil {
				log.Errorf("results JSON encoding error: %s", err.Error())
			}
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
			if fm.Sleep > 0 {
				log.Debugf("Sleep for %.1fs", fm.Sleep)
				time.Sleep(secToDuration(fm.Sleep))
			}
			continue
		}
	}
}

func (fm *Frontman) onceChan(input *Input, resultsChan chan<- Result) {
	wg := sync.WaitGroup{}

	startedAt := time.Now()
	succeed := 0

	for _, check := range input.ServiceChecks {
		wg.Add(1)
		go func(check ServiceCheck) {
			defer wg.Done()

			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				log.Errorf("serviceCheck: missing checkUuid key")
				return
			}

			res := Result{
				CheckType: "serviceCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check.Check

			if check.Check.Connect == "" {
				log.Errorf("serviceCheck: missing data.connect key")
				res.Message = "Missing data.connect key"
			} else {

				ipaddr, err := net.ResolveIPAddr("ip", check.Check.Connect)
				if err != nil {
					res.Message = err.Error()
					log.Debugf("serviceCheck: ResolveIPAddr error: %s", err.Error())
				} else {
					switch check.Check.Protocol {
					case ProtocolICMP:
						res.Measurements, err = fm.runPing(ipaddr)
						if err != nil {
							log.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
							res.Message = err.Error()
						} else {
							succeed++
						}
					case ProtocolTCP:
						port, err := check.Check.Port.Int64()

						if err != nil {
							res.Message = "Unknown port"
						} else {
							succeed++
							res.Measurements, err = fm.runTCPCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)})
							if err != nil {
								log.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
								res.Message = err.Error()
							}
						}
					case "":
						log.Errorf("serviceCheck: missing check.protocol")
						res.Message = "Missing checkKey"
					default:
						log.Errorf("serviceCheck: unknown check.protocol: '%s'", check.Check.Protocol)
						res.Message = "Unknown checkKey"
					}
				}
			}

			resultsChan <- res
		}(check)
	}

	for _, check := range input.WebChecks {
		wg.Add(1)
		go func(check WebCheck) {
			defer wg.Done()

			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				log.Errorf("webCheck: missing checkUuid key")
				return
			}

			res := Result{
				CheckType: "webCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check

			if check.Check.Method == "" {
				log.Errorf("webCheck: missing data.method key")
				res.Message = "Missing data.method key"
			} else if check.Check.URL == "" {
				log.Errorf("webCheck: missing data.url key")
				res.Message = "Missing data.url key"
			} else {
				var err error
				res.Measurements, err = fm.runWebCheck(check.Check)
				if err != nil {
					log.Debugf("webCheck: %s: %s", check.UUID, err.Error())
					res.Message = err.Error()
				} else {
					succeed++
				}
			}

			if res.Measurements["success"] == 1 {
				succeed++
			}

			resultsChan <- res
		}(check)
	}

	wg.Wait()
	close(resultsChan)

	log.Infof("%d/%d checks succeed in %.1f sec", succeed, len(input.ServiceChecks)+len(input.WebChecks), time.Since(startedAt).Seconds())
}
