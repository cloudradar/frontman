package frontman

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
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
	startedAt := time.Now()
	succeed := 0
	for _, check := range input.ServiceChecks {
		if check.Type == CheckTypeICMPPing {
			wg.Add(1)
			go func(check ServiceCheck) {
				res := fm.runPing(check)
				if res.FinalResult == 1 {
					succeed++
				}
				jsonEncoder.Encode(res)
				wg.Done()
			}(check)
		}
	}
	wg.Wait()

	log.Infof("%d/%d checks succeed in %.1f sec", succeed, len(input.ServiceChecks), time.Since(startedAt).Seconds())
	time.Sleep(secToDuration(fm.Sleep))
}
