package frontman

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/soniah/gosnmp"
)

const (
	protocolSNMPv1 = "v1"
	protocolSNMPv2 = "v2"
	protocolSNMPv3 = "v3"

	maxRepetitions = 255
)

func (fm *Frontman) runSNMPCheck(check *SNMPCheck) (map[string]interface{}, error) {
	var done = make(chan struct{})
	var err error
	var results map[string]interface{}
	go func() {
		results, err = fm.runSNMPProbe(&check.Check)
		successKey := "snmpCheck." + check.Check.Preset + ".success"
		if err != nil {
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
	params, err := buildSNMPParameters(check)
	if err != nil {
		return nil, err
	}

	err = params.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect err: %v", err)
	}
	defer params.Conn.Close()

	oids, form, err := presetToOids(check.Preset)
	if err != nil {
		return nil, err
	}
	var packets []gosnmp.SnmpPDU
	if form == "bulk" {
		result, err := params.GetBulk(oids, uint8(len(oids)), maxRepetitions)
		if err != nil {
			return nil, fmt.Errorf("get bulk err: %v", err)
		}
		packets = result.Variables
	} else {
		// walk
		for _, oid := range oids {
			pdus, err := params.BulkWalkAll(oid)
			if err != nil {
				return nil, fmt.Errorf("get bulk err: %v", err)
			}
			packets = append(packets, pdus...)
		}
	}

	return prepareSNMPResult(check.Preset, packets)
}

type snmpResult struct {
	key string
	val interface{}
}

func prepareSNMPResult(preset string, packets []gosnmp.SnmpPDU) (map[string]interface{}, error) {
	m := make(map[int][]snmpResult)

	for _, variable := range packets {
		if err := oidToError(variable.Name); err != nil {
			return nil, err
		}
		if ignoreSNMPOid(variable.Name) {
			continue
		}
		prefix, suffix, err := oidToHumanReadable(variable.Name)
		if err != nil {
			log.Debug(err)
			continue
		}

		switch variable.Type {
		case gosnmp.OctetString:
			m[suffix] = append(m[suffix], snmpResult{key: prefix, val: string(variable.Value.([]byte))})

		case gosnmp.TimeTicks, gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32:
			m[suffix] = append(m[suffix], snmpResult{key: prefix, val: variable.Value})

		default:
			log.Debugf("SNMP unhandled return type %#v for %s: %d", variable.Type, prefix, gosnmp.ToBigInt(variable.Value))
		}
	}

	m2 := make(map[string]interface{})
	if preset == "bandwidth" {
		// apply filter
		for idx, iface := range m {
			skip := false
			for _, kv := range iface {
				if kv.key == "ifOperStatus" && kv.val.(int) != 1 {
					// status is not up
					skip = true
				}
				if kv.key == "ifType" && kv.val.(int) != 6 {
					// type is not ethernetCsmacd
					skip = true
				}
			}
			if !skip {
				m3 := make(map[string]interface{})

				for _, x := range iface {
					m3[x.key] = x.val
				}
				// XXX format values as desired
				m2[fmt.Sprint(idx)] = m3
			}
		}
	} else {
		// flatten
		if len(m) != 1 {
			return nil, fmt.Errorf("unexpected index count %d", len(m))
		}
		for _, x := range m[0] {
			m2[x.key] = x.val
		}
	}
	return m2, nil
}

// generates gosnmp parameters for the given check configuration
func buildSNMPParameters(check *SNMPCheckData) (*gosnmp.GoSNMP, error) {
	params := &gosnmp.GoSNMP{
		Target:  check.Connect,
		Port:    check.Port,
		Timeout: time.Duration(check.Timeout) * time.Second,
	}

	switch check.Protocol {
	case protocolSNMPv1:
		params.Version = gosnmp.Version1
		params.Community = check.Community
	case protocolSNMPv2:
		params.Version = gosnmp.Version2c
		params.Community = check.Community
	case protocolSNMPv3:
		var err error
		params.Version = gosnmp.Version3
		params.SecurityModel = gosnmp.UserSecurityModel
		params.SecurityParameters, err = buildSNMPSecurityParameters(check)
		if err != nil {
			return nil, err
		}
		switch check.SecurityLevel {
		case "noauth":
			params.MsgFlags = gosnmp.NoAuthNoPriv
		case "auth":
			params.MsgFlags = gosnmp.AuthNoPriv
		case "priv":
			params.MsgFlags = gosnmp.AuthPriv
		default:
			return nil, fmt.Errorf("invalid security_level configuration value '%s'", check.SecurityLevel)
		}
	default:
		return nil, fmt.Errorf("invalid protocol '%s'", check.Protocol)
	}
	return params, nil
}

func buildSNMPSecurityParameters(check *SNMPCheckData) (sp *gosnmp.UsmSecurityParameters, err error) {
	sp = &gosnmp.UsmSecurityParameters{
		UserName: check.Username,
	}
	switch check.AuthenticationProtocol {
	case "sha", "sha1":
		sp.AuthenticationProtocol = gosnmp.SHA
	case "md5":
		sp.AuthenticationProtocol = gosnmp.MD5
	case "":
		sp.AuthenticationProtocol = gosnmp.NoAuth
	default:
		return sp, fmt.Errorf("invalid authentication_protocol '%s'", check.AuthenticationProtocol)
	}

	switch check.PrivacyProtocol {
	case "des":
		sp.PrivacyProtocol = gosnmp.DES
	case "":
		sp.PrivacyProtocol = gosnmp.NoPriv
	default:
		return sp, fmt.Errorf("invalid privacy_protocol '%s'", check.PrivacyProtocol)
	}

	switch check.SecurityLevel {
	case "noauth":
		sp.AuthenticationProtocol = gosnmp.NoAuth
	case "auth":
		sp.AuthenticationPassphrase = check.Password
	case "priv":
		sp.AuthenticationPassphrase = check.Password
		sp.PrivacyPassphrase = check.Password
	default:
		err = fmt.Errorf("invalid security_level configuration value '%s'", check.SecurityLevel)
	}
	return
}

// returns true if oid should be ignored
func ignoreSNMPOid(name string) bool {
	switch name {
	case ".1.3.6.1.2.1.1.2.0", // sysObjectID
		".1.3.6.1.2.1.1.7.0": // sysServices
		return true
	}
	return false
}

// returns human readable error if OID is a error
func oidToError(name string) (err error) {
	switch name {
	case ".1.3.6.1.6.3.15.1.1.3.0":
		// usmStatsUnknownUserNames
		err = errors.New("unknown user name")
	case ".1.3.6.1.6.3.15.1.1.5.0":
		// usmStatsWrongDigests
		err = errors.New("wrong digests, possibly wrong password")
	}
	return
}

// map OID to a human readable key
func oidToHumanReadable(name string) (prefix string, suffix int, err error) {
	idx := strings.LastIndex(name, ".")
	if idx == -1 {
		err = errors.New("separator missing from input")
		return
	}
	suffix, err = strconv.Atoi(name[idx+1:])
	if err != nil {
		return
	}
	name = name[0:idx]

	switch name {
	case ".1.3.6.1.2.1.1.1":
		prefix = "system.description"
	case ".1.3.6.1.2.1.1.4":
		prefix = "system.contact"
	case ".1.3.6.1.2.1.1.6":
		prefix = "system.location"
	case ".1.3.6.1.2.1.1.3":
		prefix = "system.uptime_s"
	case ".1.3.6.1.2.1.1.5":
		prefix = "system.hostname"

	// IF-MIB
	case ".1.3.6.1.2.1.2.2.1.8":
		prefix = "ifOperStatus"
	case ".1.3.6.1.2.1.2.2.1.3":
		prefix = "ifType"
	case ".1.3.6.1.2.1.31.1.1.1.1":
		prefix = "ifName"
	case ".1.3.6.1.2.1.2.2.1.2":
		prefix = "ifDescr"
	case ".1.3.6.1.2.1.2.2.1.5":
		prefix = "ifSpeed"
	case ".1.3.6.1.2.1.31.1.1.1.18":
		prefix = "ifAlias"
	case ".1.3.6.1.2.1.31.1.1.1.15":
		prefix = "ifHighSpeed"
	case ".1.3.6.1.2.1.2.2.1.10":
		prefix = "ifInOctets"
	case ".1.3.6.1.2.1.2.2.1.16":
		prefix = "ifOutOctets"

	default:
		err = fmt.Errorf("unrecognized OID %s", name)
	}
	return
}

// returns a collection of oids for the given preset
func presetToOids(preset string) (oids []string, form string, err error) {
	switch preset {
	case "basedata":
		oids = []string{
			"1.3.6.1.2.1.1.1.0", // STRING: SG350-10 10-Port Gigabit Managed Switch
			"1.3.6.1.2.1.1.3.0", // Timeticks: (575618700) 66 days, 14:56:27.00
			"1.3.6.1.2.1.1.4.0", // STRING: ops@cloudradar.io
			"1.3.6.1.2.1.1.5.0", // STRING: switch-cloudradar
			"1.3.6.1.2.1.1.6.0", // STRING: Office Berlin
		}
		form = "bulk"
	case "bandwidth":
		oids = []string{
			".1.3.6.1.2.1.2.2.1.8",     // IF-MIB::ifOperStatus (1=up)
			".1.3.6.1.2.1.2.2.1.3",     // IF-MIB::ifType (6=ethernetCsmacd)
			".1.3.6.1.2.1.31.1.1.1.1",  // IF-MIB::ifName
			".1.3.6.1.2.1.2.2.1.2",     // IF-MIB::ifDescr
			".1.3.6.1.2.1.2.2.1.5",     // IF-MIB::ifSpeed
			".1.3.6.1.2.1.31.1.1.1.18", // IF-MIB::ifAlias
			".1.3.6.1.2.1.31.1.1.1.15", // IF-MIB::ifHighSpeed
			".1.3.6.1.2.1.2.2.1.10",    // IF-MIB::ifInOctets
			".1.3.6.1.2.1.2.2.1.16",    // IF-MIB::ifOutOctets
		}
		form = "walk"
	default:
		err = fmt.Errorf("unrecognized preset %s", preset)
	}
	return
}
