package frontman

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestNeighbor(t *testing.T) {
	// XXX 1. spawn one "neighbor" on another port for the test
	// XXX 2. tell main instance to ping invalid host, see servicecheck_single_broken.json
	// XXX 3. assert neighbor is asked, and that all failed

	// XXX 4. can we somehow block main instance from succeeding while test neighbor could succeed, in order to test fallover?

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	// XXX use special config for the test
	cfg.Sleep = 10
	fm := New(cfg, DefaultCfgPath, "1.2.3")
	inputConfig := &Input{
		ServiceChecks: []ServiceCheck{{
			UUID: "neighbor1",
			Check: ServiceCheckData{
				Connect:  "greeoogle.com",
				Protocol: "icmp",
				Service:  "ping",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan

	spew.Dump(res)
	//require.Equal(t, nil, res.Message)
	//require.Equal(t, 1, res.Measurements["http.get.success"])
}
