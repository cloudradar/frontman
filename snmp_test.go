package frontman

// In order to run tests, set up snmpd somewhere and
// $ FRONTMAN_SNMPD_IP="172.16.72.169" FRONTMAN_SNMPD_COMMUNITY=public go test -v -run TestSNMP

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var snmpdIP = ""
var snmpdCommunity = ""

func skipSNMP(t *testing.T) {
	snmpdIP = os.Getenv("FRONTMAN_SNMPD_IP")
	if snmpdIP == "" {
		t.Skip("Skipping test of SNMP")
	}
	snmpdCommunity = os.Getenv("FRONTMAN_SNMPD_COMMUNITY")
}

// test SNMP v1 against snmpd
func TestSNMPv1(t *testing.T) {
	skipSNMP(t)
	// necessary snmpd.conf changes:
	// agentAddress udp:161,udp6:[::1]:161

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v1",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v1",
				Community: snmpdCommunity,
				Preset:    "basedata",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])
	require.Equal(t, true, len(res.Measurements) > 1)
	require.Equal(t, true, len(res.Measurements["system.contact"].(string)) > 1)
	require.Equal(t, true, len(res.Measurements["system.location"].(string)) > 1)
}

// test SNMP v2 against snmpd
func TestSNMPv2(t *testing.T) {
	skipSNMP(t)
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v2",
				Community: snmpdCommunity,
				Preset:    "basedata",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])
	require.Equal(t, true, len(res.Measurements) > 1)
	require.Equal(t, true, len(res.Measurements["system.contact"].(string)) > 1)
	require.Equal(t, true, len(res.Measurements["system.location"].(string)) > 1)
}

// test SNMP v2 against snmpd
func TestSNMPv2PresetBandwidth(t *testing.T) {
	// necessary snmpd.conf changes:
	// view   systemonly  included   .1

	// in order to verify IF-MIB configuration:
	// $ snmpwalk -v2c -c public hostname .1.3.6.1.2.1.2.2.1.8

	skipSNMP(t)

	delaySeconds := 1.
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = delaySeconds
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2_bandwidth",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v2",
				Community: snmpdCommunity,
				Preset:    "bandwidth",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.bandwidth.success"])

	// should be at least 1 network interface + success key in result
	require.Equal(t, true, len(res.Measurements) >= 2)

	// NOTE: test makes some assumptions that may be hard to reproduce
	// NOTE: test must be performed vs a wired connection, as snmpd don't report interface speed on wireless connections
	iface := res.Measurements["2"].(map[string]interface{})
	require.Equal(t, uint(1000), iface["ifSpeed_mbps"])
	require.Equal(t, true, len(iface["ifName"].(string)) > 0)
	require.Equal(t, true, len(iface["ifDescr"].(string)) > 0)
	require.Equal(t, 2, iface["ifIndex"])

	// do 2nd request and check delta values
	time.Sleep(time.Duration(delaySeconds) * time.Second)

	resultsChan = make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res = <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.bandwidth.success"])
	require.Equal(t, true, len(res.Measurements) >= 2)

	iface = res.Measurements["2"].(map[string]interface{})

	if _, ok := iface["ifIn_Bps"]; !ok {
		t.Errorf("ifIn_Bps key missing")
	}
	if _, ok := iface["ifInUtilization_percent"]; !ok {
		t.Errorf("ifInUtilization_percent key missing")
	}
}

func TestSNMPv2PresetOidHexValue(t *testing.T) {
	skipSNMP(t)

	delaySeconds := 1.
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = delaySeconds
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2_oid_hex",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v2",
				Community: snmpdCommunity,
				Preset:    "oid",
				Oid:       ".1.3.6.1.2.1.2.2.1.6.2", // IF-MIB::ifPhysAddress.2
				Name:      "interface mac",
				ValueType: "hex",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan

	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.oid.success"])

	part := res.Measurements[".1.3.6.1.2.1.2.2.1.6.2"].(map[string]interface{})
	require.Equal(t, true, len(part["value"].(string)) > 0)

	require.Equal(t, ".1.3.6.1.2.1.2.2.1.6.2", part["oid"].(string))
	require.Equal(t, "hex", part["value_type"].(string))
	require.Equal(t, "interface mac", part["name"].(string))
	require.Equal(t, "", part["unit"].(string))
}

func TestSNMPv2PresetOidDeltaPerSecValue(t *testing.T) {
	skipSNMP(t)

	delaySeconds := 5.
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = delaySeconds
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2_oid_delta_per_sec",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v2",
				Community: snmpdCommunity,
				Preset:    "oid",
				Oid:       ".1.3.6.1.2.1.2.2.1.16.2", //  IF-MIB::ifOutOctets.2
				ValueType: "delta_per_sec",
				Name:      "delta-per-sec-value",
				Unit:      "unit-value",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan

	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.oid.success"])

	// do 2nd request and check delta values
	time.Sleep(time.Duration(delaySeconds) * time.Second)

	resultsChan = make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res = <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.oid.success"])

	part := res.Measurements[".1.3.6.1.2.1.2.2.1.16.2"].(map[string]interface{})
	require.Equal(t, true, part["value"].(float64) >= 0)

	require.Equal(t, ".1.3.6.1.2.1.2.2.1.16.2", part["oid"].(string))
	require.Equal(t, "delta_per_sec", part["value_type"].(string))
	require.Equal(t, "delta-per-sec-value", part["name"].(string))
	require.Equal(t, "unit-value", part["unit"].(string))
}

func TestSNMPv2PresetOidDeltaValue(t *testing.T) {
	skipSNMP(t)

	delaySeconds := 5.
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = delaySeconds
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2_oid_delta",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v2",
				Community: snmpdCommunity,
				Preset:    "oid",
				Oid:       ".1.3.6.1.2.1.2.2.1.16.2", //  IF-MIB::ifOutOctets.2
				ValueType: "delta",
				Name:      "delta-value",
				Unit:      "unit-value",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan

	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.oid.success"])

	// do 2nd request and check delta values
	time.Sleep(time.Duration(delaySeconds) * time.Second)

	resultsChan = make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res = <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.oid.success"])

	part := res.Measurements[".1.3.6.1.2.1.2.2.1.16.2"].(map[string]interface{})
	require.Equal(t, true, part["value"].(float64) >= 0)

	require.Equal(t, ".1.3.6.1.2.1.2.2.1.16.2", part["oid"].(string))
	require.Equal(t, "delta", part["value_type"].(string))
	require.Equal(t, "delta-value", part["name"].(string))
	require.Equal(t, "unit-value", part["unit"].(string))
}

func TestSNMPv2PresetPorterrors(t *testing.T) {
	skipSNMP(t)

	delaySeconds := 1.
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = delaySeconds
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2_porterrors",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   5.0,
				Protocol:  "v2",
				Community: snmpdCommunity,
				Preset:    "porterrors",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.porterrors.success"])
}

// test SNMP v2 invalid community against snmpd
func TestSNMPv2InvalidCommunity(t *testing.T) {
	skipSNMP(t)
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v2_invalid_community",
			Check: SNMPCheckData{
				Connect:   snmpdIP,
				Port:      161,
				Timeout:   2.0,
				Protocol:  "v2",
				Community: "invalidCommunityName",
				Preset:    "basedata",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	// NOTE: the only error we get on invalid community name is a timeout
	require.Equal(t, "get err: Request timeout (after 0 retries)", res.Message)
	require.Equal(t, 0, res.Measurements["snmpCheck.basedata.success"])
}

// test SNMP v3 noAuthNoPriv against snmpd
func TestSNMPv3NoAuthNoPriv(t *testing.T) {
	skipSNMP(t)
	// necessary snmpd.conf changes:
	// createUser noAuthNoPrivUser
	// rouser     noAuthNoPrivUser noauth

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v3_noAuthNoPriv",
			Check: SNMPCheckData{
				Connect:       snmpdIP,
				Port:          161,
				Timeout:       5.0,
				Protocol:      "v3",
				Preset:        "basedata",
				SecurityLevel: "noAuthNoPriv",
				Username:      "noAuthNoPrivUser",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)

	// NOTE: if empty, snmpd is not configured correctly
	require.Equal(t, true, len(res.Measurements["system.contact"].(string)) > 1)

	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])
}

// test SNMP v3 noAuthNoPriv against snmpd with unknown username
func TestSNMPv3NoAuthNoPrivUnknownUser(t *testing.T) {
	skipSNMP(t)
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v3_noAuthNoPriv_unknown_user",
			Check: SNMPCheckData{
				Connect:       snmpdIP,
				Port:          161,
				Timeout:       5.0,
				Protocol:      "v3",
				Preset:        "basedata",
				SecurityLevel: "noAuthNoPriv",
				Username:      "noSuchUsername",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, "unknown user name", res.Message)
	require.Equal(t, 0, res.Measurements["snmpCheck.basedata.success"])
}

// test SNMP v3 authNoPriv against snmpd
func TestSNMPv3AuthNoPriv(t *testing.T) {
	skipSNMP(t)
	// necessary snmpd.conf changes:
	// createUser authOnlyUser  SHA "password"
	// rouser     authOnlyUser

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v3_auth",
			Check: SNMPCheckData{
				Connect:                snmpdIP,
				Port:                   161,
				Timeout:                5.0,
				Protocol:               "v3",
				Preset:                 "basedata",
				SecurityLevel:          "authNoPriv",
				Username:               "authOnlyUser",
				AuthenticationProtocol: "sha",
				AuthenticationPassword: "password",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])
	require.Equal(t, true, len(res.Measurements["system.contact"].(string)) > 1)
	require.Equal(t, true, len(res.Measurements["system.location"].(string)) > 1)
}

// test SNMP v3 authNoPriv against snmpd with wrong password
func TestSNMPv3AuthNoPrivWrongPassword(t *testing.T) {
	skipSNMP(t)
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v3_authNoPriv",
			Check: SNMPCheckData{
				Connect:                snmpdIP,
				Port:                   161,
				Timeout:                5.0,
				Protocol:               "v3",
				Preset:                 "basedata",
				SecurityLevel:          "authNoPriv",
				Username:               "authOnlyUser",
				AuthenticationProtocol: "sha",
				AuthenticationPassword: "wrongpassword",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	// NOTE: snmp protocol doesn't have a specific error message for wrong password
	require.Equal(t, "wrong digests, possibly wrong password", res.Message)
	require.Equal(t, 0, res.Measurements["snmpCheck.basedata.success"])
}

// test SNMP v3 authPriv against snmpd
func TestSNMPv3AuthPriv(t *testing.T) {
	skipSNMP(t)
	// necessary snmpd.conf changes:
	// createUser authPrivUser  SHA "password" DES
	// rwuser   authPrivUser   priv

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v3_priv",
			Check: SNMPCheckData{
				Connect:                snmpdIP,
				Port:                   161,
				Timeout:                5.0,
				Protocol:               "v3",
				Preset:                 "basedata",
				SecurityLevel:          "authPriv",
				Username:               "authPrivUser",
				AuthenticationProtocol: "sha",
				AuthenticationPassword: "password",
				PrivacyProtocol:        "des",
				PrivacyPassword:        "password",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])
	require.Equal(t, true, len(res.Measurements["system.contact"].(string)) > 1)
	require.Equal(t, true, len(res.Measurements["system.location"].(string)) > 1)
}

func TestSNMPv3PresetBandwidthWrongCredentials(t *testing.T) {
	// this test makes sure that we error out if called with invalid credentials (SNMP v3)

	skipSNMP(t)

	delaySeconds := 1.
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = delaySeconds
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		SNMPChecks: []SNMPCheck{{
			UUID: "snmp_basedata_v3_bandwidth_wrong_credentials",
			Check: SNMPCheckData{
				Connect:                snmpdIP,
				Port:                   161,
				Timeout:                5.0,
				Protocol:               "v3",
				Preset:                 "bandwidth",
				SecurityLevel:          "authNoPriv",
				Username:               "authOnlyUser",
				AuthenticationProtocol: "sha",
				AuthenticationPassword: "wrongpassword",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan

	require.Equal(t, "wrong digests, possibly wrong password", res.Message)
	require.Equal(t, 0, res.Measurements["snmpCheck.bandwidth.success"])
}

func TestOidToHumanReadable(t *testing.T) {
	v, suffix, err := oidToHumanReadable(".1.3.6.1.2.1.2.2.1.8.1")
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, suffix)
	assert.Equal(t, "ifOperStatus", v)

	v, suffix, err = oidToHumanReadable(".1.3.6.1.2.1.2.2.1.8.2")
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, suffix)
	assert.Equal(t, "ifOperStatus", v)
}

func TestDelta(t *testing.T) {
	assert.Equal(t, uint(1), delta(1, 2))
	assert.Equal(t, uint(1), delta(2, 1))
}
