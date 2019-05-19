package frontman

// In order to run tests, set up snmpd somewhere and
// $ FRONTMAN_SNMPD_IP="172.16.72.144" go test -v

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var snmpdIP = ""

func skipSNMP(t *testing.T) {
	snmpdIP = os.Getenv("FRONTMAN_SNMPD_IP")
	if snmpdIP == "" {
		t.Skip("Skipping test of SNMP")
	}
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
				Timeout:   1.0,
				Protocol:  "v1",
				Community: "public",
				Preset:    "basedata",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])

	// test against default values from ubuntu snmpd.conf
	assert.Equal(t, "Me <me@example.org>", res.Measurements["system.contact"])
	assert.Equal(t, "ubuntu", res.Measurements["system.hostname"])
	assert.Equal(t, "Sitting on the Dock of the Bay", res.Measurements["system.location"])
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
				Timeout:   1.0,
				Protocol:  "v2",
				Community: "public",
				Preset:    "basedata",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])

	// test against default values from ubuntu snmpd.conf
	assert.Equal(t, "Me <me@example.org>", res.Measurements["system.contact"])
	assert.Equal(t, "ubuntu", res.Measurements["system.hostname"])
	assert.Equal(t, "Sitting on the Dock of the Bay", res.Measurements["system.location"])
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
				Timeout:   1.0,
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
	require.Equal(t, "get bulk err: Request timeout (after 0 retries)", res.Message)
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
				Timeout:       1.0,
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
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])

	// test against default values from ubuntu snmpd.conf
	assert.Equal(t, "Me <me@example.org>", res.Measurements["system.contact"])
	assert.Equal(t, "ubuntu", res.Measurements["system.hostname"])
	assert.Equal(t, "Sitting on the Dock of the Bay", res.Measurements["system.location"])
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
				Timeout:       1.0,
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
				Timeout:                1.0,
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

	// test against default values from ubuntu snmpd.conf
	assert.Equal(t, "Me <me@example.org>", res.Measurements["system.contact"])
	assert.Equal(t, "ubuntu", res.Measurements["system.hostname"])
	assert.Equal(t, "Sitting on the Dock of the Bay", res.Measurements["system.location"])
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
				Timeout:                1.0,
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
				Timeout:                1.0,
				Protocol:               "v3",
				Preset:                 "basedata",
				SecurityLevel:          "authPriv",
				Username:               "authPrivUser",
				AuthenticationProtocol: "sha",
				AuthenticationPassword: "password",
				PrivacyProtocol:        "des",
				PrivacyPassword:        "password", // XXX
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["snmpCheck.basedata.success"])

	// test against default values from ubuntu snmpd.conf
	assert.Equal(t, "Me <me@example.org>", res.Measurements["system.contact"])
	assert.Equal(t, "ubuntu", res.Measurements["system.hostname"])
	assert.Equal(t, "Sitting on the Dock of the Bay", res.Measurements["system.location"])
}
