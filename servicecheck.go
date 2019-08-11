package frontman

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (fm *Frontman) runServiceCheck(check ServiceCheck) (map[string]interface{}, error) {
	var done = make(chan struct{})
	var err error
	var results map[string]interface{}
	go func() {
		ipaddr, resolveErr := resolveIPAddrWithTimeout(check.Check.Connect, timeoutDNSResolve)
		if resolveErr != nil {
			err = fmt.Errorf("resolve ip error: %s", resolveErr.Error())
			logrus.Debugf("serviceCheck: ResolveIPAddr error: %s", resolveErr.Error())
			done <- struct{}{}
			return
		}

		switch check.Check.Protocol {
		case ProtocolICMP:
			results, err = fm.runPing(ipaddr)
			if err != nil {
				logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
			}
		case ProtocolTCP:
			port, _ := check.Check.Port.Int64()

			results, err = fm.runTCPCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)}, check.Check.Connect, check.Check.Service)
			if err != nil {
				logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
			}
		case ProtocolSSL:
			port, _ := check.Check.Port.Int64()

			results, err = fm.runSSLCheck(&net.TCPAddr{IP: ipaddr.IP, Port: int(port)}, check.Check.Connect, check.Check.Service)
			if err != nil {
				logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
			}
		case "":
			logrus.Info("serviceCheck: missing check.protocol")
			err = errors.New("Missing check.protocol")
		default:
			logrus.Errorf("serviceCheck: unknown check.protocol: '%s'", check.Check.Protocol)
			err = errors.New("Unknown check.protocol")
		}
		done <- struct{}{}
	}()

	// Warning: do not rely on serviceCheckEmergencyTimeout as it leak goroutines(until it will be finished)
	// instead use individual timeouts inside all checks
	select {
	case <-done:
		return results, err
	case <-time.After(serviceCheckEmergencyTimeout):
		logrus.Errorf("serviceCheck: %s got unexpected timeout after %.0fs", check.UUID, serviceCheckEmergencyTimeout.Seconds())
		return nil, fmt.Errorf("got unexpected timeout")
	}
}

func resolveIPAddrWithTimeout(addr string, timeout time.Duration) (*net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, addr)
	if err != nil {
		return nil, err
	}

	if len(ipAddrs) == 0 {
		return nil, errors.New("can't resolve host")
	}

	ipAddr := ipAddrs[0]
	return &ipAddr, nil
}

func runServiceChecks(fm *Frontman, wg *sync.WaitGroup, resultsChan chan<- Result, checkList []ServiceCheck) int {
	succeed := 0
	for _, check := range checkList {
		wg.Add(1)
		go func(check ServiceCheck) {
			defer wg.Done()

			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				logrus.Info("serviceCheck: missing checkUuid key")
				return
			}

			res := Result{
				CheckType: "serviceCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check.Check

			if check.Check.Connect == "" {
				logrus.Info("serviceCheck: missing data.connect key")
				res.Message = "Missing data.connect key"
			} else {
				var err error
				res.Measurements, err = fm.runServiceCheck(check)
				if err != nil {
					recovered := false
					if fm.Config.FailureConfirmation > 0 {
						logrus.Debugf("serviceCheck failed, retrying up to %d times: %s: %s", fm.Config.FailureConfirmation, check.UUID, err.Error())

						for i := 1; i <= fm.Config.FailureConfirmation; i++ {
							time.Sleep(time.Duration(fm.Config.FailureConfirmationDelay*1000) * time.Millisecond)
							logrus.Debugf("Retry %d for failed check %s", i, check.UUID)
							res.Measurements, err = fm.runServiceCheck(check)
							if err == nil {
								recovered = true
								break
							}
						}
					}
					if !recovered && fm.Config.AskNeigbors && check.Check.Protocol != "ssl" {
						// NOTE: ssl checks are excluded from "ask neighbor" feature
						checkRequest := &Input{
							ServiceChecks: []ServiceCheck{check},
						}
						data, _ := json.Marshal(checkRequest)
						fm.askNeighbors(data, &res)
					}

					if !recovered {
						logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
						res.Message = err.Error()
					}
				}

				if res.Message == nil {
					succeed++
				}
			}

			resultsChan <- res
		}(check)
	}
	return succeed
}
