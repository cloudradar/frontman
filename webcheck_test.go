package frontman

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestPreventDoubleRunOfChecks(t *testing.T) {
	// verifies that we prevent frontman starting another check with the same uuid while the first has not finished yet
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = 10
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	inputConfig := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:            2.0,
				URL:                "https://h1.hostgum.eu/sleep.php?t=1",
				Method:             "get",
				ExpectedHTTPStatus: 200,
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["http.get.success"])

	spew.Dump(res)
}
