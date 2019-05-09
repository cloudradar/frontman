package frontman

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/soniah/gosnmp"
)

const ProtocolSNMPv1 = "v1"
const ProtocolSNMPv2 = "v2"
const ProtocolSNMPv3 = "v3"

func (fm *Frontman) runSNMPCheck(check SNMPCheck) (map[string]interface{}, error) {
	var done = make(chan struct{})
	var err error
	var results map[string]interface{}
	go func() {
		results, err = fm.runSNMPProbe(&check.Check)
		successKey := "snmpCheck." + check.Check.Preset + ".success"
		if err != nil {
			log.Debugf("snmpCheck: %s: %s", check.UUID, err.Error())
			results[successKey] = 0
		} else {
			results[successKey] = 1
		}
		done <- struct{}{}
	}()

	// Warning: do not rely on serviceCheckEmergencyTimeout as it leak goroutines(until it will be finished)
	// instead use individual timeouts inside all checks
	select {
	case <-done:
		return results, err
	case <-time.After(serviceCheckEmergencyTimeout):
		log.Errorf("snmpCheck: %s got unexpected timeout after %.0fs", check.UUID, serviceCheckEmergencyTimeout.Seconds())
		return nil, fmt.Errorf("got unexpected timeout")
	}
}

func (fm *Frontman) runSNMPProbe(check *SNMPCheckData) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	params := &gosnmp.GoSNMP{
		Target:    check.Connect,
		Port:      check.Port,
		Community: check.Community,
		Timeout:   time.Duration(check.Timeout) * time.Second,
	}

	switch check.Protocol {
	case ProtocolSNMPv1:
		params.Version = gosnmp.Version1
	case ProtocolSNMPv2:
		params.Version = gosnmp.Version2c
	case ProtocolSNMPv3:
		// XXX auth stuff
		return m, errors.New("SNMP v3 not implemented")
	default:
		log.Errorf("snmpCheck: unknown check.protocol: '%s'", check.Protocol)
		return m, errors.New("Unknown check.protocol")
	}

	err := params.Connect()
	if err != nil {
		return m, fmt.Errorf("Connect err: %v", err)
	}
	defer params.Conn.Close()

	oids, err := mapSnmpPreset(check.Preset)
	if err != nil {
		return m, err
	}

	result, err := params.GetBulk(oids, uint8(len(oids)), 255)
	if err != nil {
		return m, fmt.Errorf("Get err: %v", err)
	}

	for _, variable := range result.Variables {
		prefix, err := snmpOidHumanName(variable.Name)
		if err != nil {
			log.Debug(err)
			continue
		}
		switch variable.Type {
		case gosnmp.OctetString:
			m[prefix] = string(variable.Value.([]byte))

		case gosnmp.TimeTicks:
			m[prefix] = variable.Value

		default:
			log.Debugf("SNMP unhandled return type %#v for %s: %d", variable.Type, prefix, gosnmp.ToBigInt(variable.Value))
		}
	}
	return m, nil
}

// map OID to a human readable key
func snmpOidHumanName(name string) (prefix string, err error) {
	switch name {
	case ".1.3.6.1.2.1.1.1.0":
		prefix = "system.description"
	case ".1.3.6.1.2.1.1.4.0":
		prefix = "system.contact"
	case ".1.3.6.1.2.1.1.6.0":
		prefix = "system.location"
	case ".1.3.6.1.2.1.1.3.0":
		prefix = "system.uptime_s"
	case ".1.3.6.1.2.1.1.5.0":
		prefix = "system.hostname"
	default:
		err = fmt.Errorf("Unrecognized SNMP variable %s", name)
	}
	return
}
func mapSnmpPreset(preset string) (oids []string, err error) {

	switch preset {
	case "basedata":
		oids = []string{
			"1.3.6.1.2.1.1.1.0", // STRING: SG350-10 10-Port Gigabit Managed Switch
			"1.3.6.1.2.1.1.3.0", // Timeticks: (575618700) 66 days, 14:56:27.00
			"1.3.6.1.2.1.1.4.0", // STRING: ops@cloudradar.io
			"1.3.6.1.2.1.1.5.0", // STRING: switch-cloudradar
			"1.3.6.1.2.1.1.6.0", // STRING: Office Berlin
		}
	default:
		err = fmt.Errorf("Unrecognized preset %s", preset)
	}

	return
}
