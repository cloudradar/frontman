package frontman

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSUDPCheck(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	inputConfig := &Input{
		ServiceChecks: []ServiceCheck{{
			UUID: "dns-udp-check",
			Check: ServiceCheckData{
				Connect:  "8.8.8.8",
				Protocol: "udp",
				Service:  "dns",
				Port:     53,
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["net.udp.dns.53.success"])
}

func TestDNSTCPCheck(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	inputConfig := &Input{
		ServiceChecks: []ServiceCheck{{
			UUID: "dns-tcp-check",
			Check: ServiceCheckData{
				Connect:  "8.8.8.8",
				Protocol: "tcp",
				Service:  "dns",
				Port:     53,
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["net.tcp.dns.53.success"])
}
