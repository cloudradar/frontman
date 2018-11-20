package frontman

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	log "github.com/sirupsen/logrus"
)

func InputFromFile(filename string) (*Input, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("parseInputFromFile: '%s' failed to read the file: %s", filename, err.Error())
	}

	var i Input
	err = json.Unmarshal(b, &i)
	if err != nil {
		return nil, fmt.Errorf("parseInputFromFile: '%s' JSON unmarshal error: %s", filename, err.Error())
	}
	return &i, nil
}

func (fm *Frontman) initHubHttpClient() {
	if fm.hubHttpClient == nil {
		tr := *(http.DefaultTransport.(*http.Transport))
		if fm.rootCAs != nil {
			tr.TLSClientConfig = &tls.Config{RootCAs: fm.rootCAs}
		}
		if fm.HubProxy != "" {
			if !strings.HasPrefix(fm.HubProxy, "http://") {
				fm.HubProxy = "http://" + fm.HubProxy
			}

			u, err := url.Parse(fm.HubProxy)

			if err != nil {
				log.Errorf("Failed to parse 'hub_proxy' URL")
			} else {
				if fm.HubProxyUser != "" {
					u.User = url.UserPassword(fm.HubProxyUser, fm.HubProxyPassword)
				}
				tr.Proxy = func(_ *http.Request) (*url.URL, error) {
					return u, nil
				}
			}
		}

		fm.hubHttpClient = &http.Client{
			Timeout:   time.Second * 30,
			Transport: &tr,
		}
	}
}

func (fm *Frontman) InputFromHub() (*Input, error) {
	fm.initHubHttpClient()

	i := Input{}
	r, err := http.NewRequest("GET", fm.HubURL, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Add("User-Agent", fm.userAgent())

	if fm.HubUser != "" {
		r.SetBasicAuth(fm.HubUser, fm.HubPassword)
	}

	resp, err := fm.hubHttpClient.Do(r)

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
	fm.initHubHttpClient()

	var err error
	var hostInfo MeasurementsMap

	if !fm.hostInfoSent {
		// Fetch hostInfo
		hostInfo, err = fm.HostInfoResults()
		// TODO: Do we need special handling in error case? Send a special error object to the hub?
		if err != nil {
			log.Warnf("Failed to fetch HostInfo: %s", err)
			hostInfo["error"] = err.Error()
		}
	}

	fm.offlineResultsBuffer = append(fm.offlineResultsBuffer, results...)
	// Bundle hostInfo and results
	b, err := json.Marshal(Results{
		Results:  fm.offlineResultsBuffer,
		HostInfo: hostInfo,
	})

	if err != nil {
		return err
	}

	// in case buffer + results exceed HubMaxOfflineBufferBytes, reset buffer
	if len(b) > fm.HubMaxOfflineBufferBytes && len(fm.offlineResultsBuffer) > 0 {
		log.Errorf("hub_max_offline_buffer_bytes(%d bytes) exceed with %d results. Flushing the buffer...", fm.HubMaxOfflineBufferBytes, len(results))

		fm.offlineResultsBuffer = []Result{}
		b, err = json.Marshal(Results{Results: results, HostInfo: hostInfo})
		if err != nil {
			return err
		}
	}

	var req *http.Request

	if fm.HubGzip {
		var buffer bytes.Buffer
		zw := gzip.NewWriter(&buffer)
		zw.Write(b)
		zw.Close()
		req, err = http.NewRequest("POST", fm.HubURL, &buffer)
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req, err = http.NewRequest("POST", fm.HubURL, bytes.NewBuffer(b))
	}
	if err != nil {
		return err
	}

	req.Header.Add("User-Agent", fm.userAgent())

	if fm.HubUser != "" {
		req.SetBasicAuth(fm.HubUser, fm.HubPassword)
	}

	resp, err := fm.hubHttpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	log.Debugf("Sent %d results to HUB.. Status %d", len(results), resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return errors.New(resp.Status)
	}

	// We assume the hostInfo was successfully sent because the responnse code
	// was ok and hostInfo will only be sent if the flag was flase before.
	if !fm.hostInfoSent {
		fm.hostInfoSent = true
		log.Debugf("hostInfoSent was set to true")
	}

	// in case of successful POST reset the offline buffer
	fm.offlineResultsBuffer = []Result{}

	return nil
}

func (fm *Frontman) Run(inputFilePath *string, outputFile *os.File, interrupt chan struct{}, once bool) {
	var jsonEncoder *json.Encoder
	if fm.PidFile != "" && !once && runtime.GOOS != "windows" {
		err := ioutil.WriteFile(fm.PidFile, []byte(strconv.Itoa(os.Getpid())), 0664)

		if err != nil {
			log.Errorf("Failed to write pid file at: %s", fm.PidFile)
		}
	}

	if outputFile != nil {
		jsonEncoder = json.NewEncoder(outputFile)
	}

	sendResultsTicker := time.Tick(secToDuration(fm.SenderModeInterval))

	outputLock := sync.Mutex{}

	for true {
		var results []Result
		var input *Input
		var err error
		if inputFilePath == nil || *inputFilePath == "" {
			input, err = fm.InputFromHub()

			if err != nil {
				auth := ""
				if fm.HubUser != "" {
					auth = fmt.Sprintf(" (%s:***)", fm.HubUser)
				}
				log.Errorf("InputFromHub%s: %s", auth, err.Error())
			}
		} else {
			input, err = InputFromFile(*inputFilePath)

			if err != nil {
				log.Errorf("InputFromFile(%s) error: %s", *inputFilePath, err.Error())
			}
		}

		// in case HUB server will hang on response we will need a buffer to continue perform checks
		resultsChan := make(chan Result, 100)

		if input != nil {
			go fm.onceChan(input, resultsChan)
		} else {
			close(resultsChan)
		}

		if outputFile != nil && once {
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
		case <-time.After(secToDuration(fm.Sleep)):
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
						port, _ := check.Check.Port.Int64()

						res.Measurements, err = fm.runTCPCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)}, check.Check.Connect, check.Check.Service)
						if err != nil {
							log.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
							res.Message = err.Error()
						} else {
							succeed++
						}
					case ProtocolSSL:
						port, _ := check.Check.Port.Int64()

						res.Measurements, err = fm.runSSLCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)}, check.Check.Connect, check.Check.Service)
						if err != nil {
							log.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
							res.Message = err.Error()
						} else {
							succeed++
						}
					case "":
						log.Errorf("serviceCheck: missing check.protocol")
						res.Message = "Missing check.protocol"
					default:
						log.Errorf("serviceCheck: unknown check.protocol: '%s'", check.Check.Protocol)
						res.Message = "Unknown check.protocol"
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

			res.Check = check.Check

			if check.Check.Method == "" {
				log.Errorf("webCheck: missing check.method key")
				res.Message = "Missing check.method key"
			} else if check.Check.URL == "" {
				log.Errorf("webCheck: missing check.url key")
				res.Message = "Missing check.url key"
			} else {
				var err error
				res.Measurements, err = fm.runWebCheck(check.Check)
				if err != nil {
					log.Debugf("webCheck: %s: %s", check.UUID, err.Error())
					res.Message = err.Error()
				}
			}

			if res.Message == nil {
				succeed++
			}

			resultsChan <- res
		}(check)
	}

	wg.Wait()
	close(resultsChan)

	log.Infof("%d/%d checks succeed in %.1f sec", succeed, len(input.ServiceChecks)+len(input.WebChecks), time.Since(startedAt).Seconds())
}

// HostInfoResults fetches information about the host itself which can be
// send to the hub alongside measurements.
func (fm *Frontman) HostInfoResults() (MeasurementsMap, error) {
	res := MeasurementsMap{}

	if len(fm.SystemFields) == 0 {
		log.Warnf("[SYSTEM] HostInfoResults called but no SystemFields are defined.")
		return res, fmt.Errorf("No system_fields defined")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	info, err := host.InfoWithContext(ctx)
	errs := []string{}

	if err != nil {
		log.Errorf("[SYSTEM] Failed to read host info: %s", err.Error())
		errs = append(errs, err.Error())
	}

	for _, field := range fm.SystemFields {
		switch strings.ToLower(field) {
		case "os_kernel":
			if info != nil {
				res[field] = info.OS
			} else {
				res[field] = nil
			}
		case "os_family":
			if info != nil {
				res[field] = info.PlatformFamily
			} else {
				res[field] = nil
			}
		case "uname":
			uname, err := Uname()
			if err != nil {
				log.Errorf("[SYSTEM] Failed to read host uname: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
			} else {
				res[field] = uname
			}
		case "fqdn":
			res[field] = getFQDN()
		case "cpu_model":
			cpuInfo, err := cpu.Info()
			if err != nil {
				log.Errorf("[SYSTEM] Failed to read cpu info: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}

			res[field] = cpuInfo[0].ModelName
		case "os_arch":
			res[field] = runtime.GOARCH
		case "memory_total_b":
			memStat, err := mem.VirtualMemory()
			if err != nil {
				log.Errorf("[SYSTEM] Failed to read mem info: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}

			res[field] = memStat.Total
		}
	}

	if len(errs) == 0 {
		return res, nil
	}

	return res, errors.New("SYSTEM: " + strings.Join(errs, "; "))
}
