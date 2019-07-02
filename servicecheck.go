package frontman

import (
	"context"
	"fmt"
	"net"
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
