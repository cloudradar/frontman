package frontman

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebCheck(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = 10
	fm := New(cfg, DefaultCfgPath, "1.2.3")
	inputConfig := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:            1.0,
				URL:                "https://www.google.com",
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
}
