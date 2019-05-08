package frontman

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/soniah/gosnmp"
)

const ProtocolSNMPv2 = "v2"
const ProtocolSNMPv3 = "v3"

func (fm *Frontman) runSNMPCheck(check SNMPCheck) (map[string]interface{}, error) {
	fmt.Println("runSNMPCheck")
	var done = make(chan struct{})
	var err error
	var results map[string]interface{}
	go func() {
		switch check.Check.Protocol {
		case ProtocolSNMPv2:
			results, err = fm.runSNMPv2Probe(&check.Check)
			if err != nil {
				log.Debugf("snmpCheck: %s: %s", check.UUID, err.Error())
			}
		default:
			log.Errorf("snmpCheck: unknown check.protocol: '%s'", check.Check.Protocol)
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
		log.Errorf("snmpCheck: %s got unexpected timeout after %.0fs", check.UUID, serviceCheckEmergencyTimeout.Seconds())
		return nil, fmt.Errorf("got unexpected timeout")
	}
}

func (fm *Frontman) runSNMPv2Probe(check *SNMPCheckData) (m map[string]interface{}, err error) {
	m = make(map[string]interface{})

	// XXX apply args from check
	params := &gosnmp.GoSNMP{
		Target:    "10.10.30.175",
		Port:      161,
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   time.Duration(1) * time.Second,
		/* v3 stuff:
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "user",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "password",
			PrivacyProtocol:          gosnmp.DES,
			PrivacyPassphrase:        "password",
		},
		*/
	}

	err = params.Connect()
	if err != nil {
		log.Fatalf("SNMP Connect() err: %v", err)
	}
	defer params.Conn.Close()

	// preset "basedata"
	basedataOids := []string{
		"1.3.6.1.2.1.1.1.0", // STRING: SG350-10 10-Port Gigabit Managed Switch
		"1.3.6.1.2.1.1.3.0", // Timeticks: (575618700) 66 days, 14:56:27.00
		"1.3.6.1.2.1.1.4.0", // STRING: ops@cloudradar.io
		"1.3.6.1.2.1.1.5.0", // STRING: switch-cloudradar
		"1.3.6.1.2.1.1.6.0", // STRING: Office Berlin
	}
	result, err2 := params.Get(basedataOids)
	if err2 != nil {
		log.Fatalf("SNMP Get() err: %v", err2)
	}

	for _, variable := range result.Variables {
		prefix := variable.Name
		//fmt.Printf("oid: %s ", variable.Name)

		switch variable.Type {
		case gosnmp.OctetString:
			// fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
			m[prefix] = string(variable.Value.([]byte))

		case gosnmp.TimeTicks:
			//fmt.Printf("TimeTicks: %d\n", variable.Value)
			m[prefix] = variable.Value

		default:
			fmt.Printf("SNMP unhandled return type %#v: %d\n", variable.Type, gosnmp.ToBigInt(variable.Value))
		}
	}

	return
}
