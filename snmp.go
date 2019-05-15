package frontman

import (
	"fmt"
	"math"
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

// used to calculate delta from last snmp bandwidth measure
type snmpBandwidthMeasure struct {
	timestamp   time.Time
	ifName      string
	ifOutOctets uint
	ifInOctets  uint
}

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
	m := make(map[string]interface{})
	params, err := buildSNMPParameters(check)
	if err != nil {
		return m, err
	}

	err = params.Connect()
	if err != nil {
		return m, fmt.Errorf("connect err: %v", err)
	}
	defer params.Conn.Close()

	oids, form, err := presetToOids(check.Preset)
	if err != nil {
		return m, err
	}
	var packets []gosnmp.SnmpPDU
	if form == "bulk" {
		result, err := params.GetBulk(oids, uint8(len(oids)), maxRepetitions)
		if err != nil {
			return m, fmt.Errorf("get bulk err: %v", err)
		}
		packets = result.Variables
	} else {
		// walk
		for _, oid := range oids {
			pdus, err := params.BulkWalkAll(oid)
			if err != nil {
				return m, fmt.Errorf("bulk walk all err: %v", err)
			}
			packets = append(packets, pdus...)
		}
	}

	return fm.prepareSNMPResult(check.Preset, packets)
}

type snmpResult struct {
	key string
	val interface{}
}

func (fm *Frontman) prepareSNMPResult(preset string, packets []gosnmp.SnmpPDU) (map[string]interface{}, error) {
	res := make(map[int][]snmpResult)
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
			res[suffix] = append(res[suffix], snmpResult{key: prefix, val: string(variable.Value.([]byte))})

		case gosnmp.TimeTicks, gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32:
			res[suffix] = append(res[suffix], snmpResult{key: prefix, val: variable.Value})

		default:
			log.Debugf("SNMP unhandled return type %#v for %s: %d", variable.Type, prefix, gosnmp.ToBigInt(variable.Value))
		}
	}
	return fm.filterSNMPResult(preset, res)
}

const (
	ifOperStatusUp       = 1
	ifTypeEthernetCsmacd = 6
)

// returns true if snmpResult is part of a network interface that should be excluded
func (kv snmpResult) shouldExcludeInterface() bool {
	if kv.key == "ifOperStatus" && kv.val.(int) != ifOperStatusUp {
		return true
	}
	if kv.key == "ifType" && kv.val.(int) != ifTypeEthernetCsmacd {
		return true
	}
	return false
}

// filters the snmp results according to preset
func (fm *Frontman) filterSNMPResult(preset string, res map[int][]snmpResult) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	if preset == "bandwidth" {
		prevMeasures := fm.previousSNMPBandwidthMeasure
		fm.previousSNMPBandwidthMeasure = nil
		for idx, iface := range res {
			skip := false
			for _, kv := range iface {
				if kv.shouldExcludeInterface() {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			m[fmt.Sprint(idx)] = fm.filterSNMPBandwidthResult(idx, iface, prevMeasures)
		}
	} else {
		// flatten
		if len(res) != 1 {
			return nil, fmt.Errorf("unexpected index count %d", len(res))
		}
		for _, x := range res[0] {
			m[x.key] = x.val
		}
	}
	return m, nil
}

func (fm *Frontman) filterSNMPBandwidthResult(idx int, iface []snmpResult, prevMeasures []snmpBandwidthMeasure) map[string]interface{} {
	m := make(map[string]interface{})

	ifIn := uint(0)
	ifOut := uint(0)
	ifName := ""
	ifSpeedInBytes := uint(0)
	for _, x := range iface {
		key := x.key
		switch x.key {
		case "ifOperStatus", "ifType":
			continue
		case "ifName":
			ifName = x.val.(string)
		case "ifInOctets":
			ifIn = x.val.(uint)
		case "ifOutOctets":
			ifOut = x.val.(uint)
		case "ifSpeed":
			key = "ifSpeed_mbps"
			if x.val.(uint) > 0 {
				x.val = x.val.(uint) / 1000000 // megabits
				ifSpeedInBytes = (x.val.(uint) * 1000000) / 8
			}
		}
		m[key] = x.val
	}
	m["ifIndex"] = idx

	// calculate delta from previous measure
	for _, measure := range prevMeasures {
		if measure.ifName == ifName && ifSpeedInBytes > 0 {
			delaySeconds := float64(time.Since(measure.timestamp) / time.Second)
			inDelta := float64(delta(measure.ifInOctets, ifIn))
			outDelta := float64(delta(measure.ifOutOctets, ifOut))
			inPct := (inDelta / (float64(ifSpeedInBytes) * delaySeconds)) * 100
			outPct := (outDelta / (float64(ifSpeedInBytes) * delaySeconds)) * 100
			m["ifInUtilization_percent"] = math.Round(inPct*100) / 100
			m["ifOutUtilization_percent"] = math.Round(outPct*100) / 100
			m["ifIn_Bps"] = uint(math.Round(inDelta / delaySeconds))
			m["ifOut_Bps"] = uint(math.Round(outDelta / delaySeconds))
			break
		}
	}

	fm.previousSNMPBandwidthMeasure = append(fm.previousSNMPBandwidthMeasure, snmpBandwidthMeasure{
		timestamp:   time.Now(),
		ifName:      ifName,
		ifOutOctets: ifOut,
		ifInOctets:  ifIn,
	})

	return m
}

func delta(v1, v2 uint) uint {
	if v1 < v2 {
		return v2 - v1
	}
	return v1 - v2
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
			".1.3.6.1.2.1.2.2.1.10",    // IF-MIB::ifInOctets
			".1.3.6.1.2.1.2.2.1.16",    // IF-MIB::ifOutOctets
		}
		form = "walk"
	default:
		err = fmt.Errorf("unrecognized preset %s", preset)
	}
	return
}
