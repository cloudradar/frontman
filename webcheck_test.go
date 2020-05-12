package frontman

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebCheck(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
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

func TestWebCheckHeaders(t *testing.T) {
	// verifies that extra headers are being set in http requests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		assert.Equal(t, "Basic dXNlcm5hbWU6cGFzc3dvcmQ=", r.Header.Get("Authorization"))
		assert.Equal(t, "no-cache", r.Header.Get("Cache-Control"))
	}))
	defer ts.Close()

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	inputConfig := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:            1.0,
				URL:                ts.URL,
				Method:             "get",
				ExpectedHTTPStatus: 200,
				Headers: map[string]string{
					"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
					"cache-control": "no-cache",
				},
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(inputConfig, resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["http.get.success"])
}
