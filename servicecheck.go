package frontman

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (check ServiceCheck) uniqueID() string {
	return check.UUID
}

func (check ServiceCheck) run(fm *Frontman) (*Result, error) {

	res := &Result{
		Node:      fm.Config.NodeName,
		CheckType: "serviceCheck",
		CheckUUID: check.UUID,
		Check:     check.Check,
		Timestamp: time.Now().Unix(),
	}

	if check.UUID == "" {
		return res, fmt.Errorf("missing checkUuid key")
	}
	if check.Check.Connect == "" {
		return res, fmt.Errorf("missing data.connect key")
	}

	var done = make(chan struct{})
	var err error
	var results map[string]interface{}

	go func() {
		switch check.Check.Protocol {
		case ProtocolICMP:
			results, err = fm.runPing(check.Check.Connect)
			if err != nil {
				logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
			}
		case ProtocolTCP:
			port, _ := check.Check.Port.Int64()

			results, err = fm.runTCPCheck(check.Check.Connect, int(port), check.Check.Service)
			if err != nil {
				logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
			}
		case ProtocolUDP:
			port, _ := check.Check.Port.Int64()

			results, err = fm.runUDPCheck(check.Check.Connect, int(port), check.Check.Service)
			if err != nil {
				logrus.Debugf("serviceCheck: %s: %s", check.UUID, err.Error())
			}
		case ProtocolSSL:
			port, _ := check.Check.Port.Int64()

			results, err = fm.runSSLCheck(check.Check.Connect, int(port), check.Check.Service)
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
		res.Measurements = results
		return res, err
	case <-time.After(serviceCheckEmergencyTimeout):
		logrus.Errorf("serviceCheck %s %s: %s got unexpected timeout after %.0fs", check.Check.Protocol, check.Check.Connect, check.UUID, serviceCheckEmergencyTimeout.Seconds())
		return res, fmt.Errorf("got unexpected timeout")
	}
}
