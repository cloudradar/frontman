package frontman

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"runtime"
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

func (fm *Frontman) Run(input *Input, output io.Writer, interrupt chan struct{}) {
	if runtime.GOOS == "windows" {
		log.Error("⚠️ You need to run frontman as administrator in order to use ICMP ping on Windows")
	}
	for true {
		fm.Once(input, output)
		select {
		case <-interrupt:
			return
		default:
			if fm.OneRunOnly {
				return
			}
			continue
		}
	}
}

func (fm *Frontman) Once(input *Input, output io.Writer) {
	jsonEncoder := json.NewEncoder(output)
	wg := sync.WaitGroup{}
	outputLock := sync.Mutex{}
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
					port, _ := check.Data.Port.Int64()

					res.Data.Measurements, res.FinalResult, res.Data.Message = fm.runTCPCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)})
				default:
					res.Data.Message = "Unknown checkKey"
				}
			}

			if res.FinalResult == 1 {
				succeed++
			}

			outputLock.Lock()
			defer outputLock.Unlock()
			jsonEncoder.Encode(res)
		}(check)
	}

	wg.Wait()

	log.Infof("%d/%d checks succeed in %.1f sec", succeed, len(input.ServiceChecks), time.Since(startedAt).Seconds())
	time.Sleep(secToDuration(fm.Sleep))
}
