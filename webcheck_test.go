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
	cfg.HTTPCheckTimeout = 10.0
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	input := &Input{
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
	fm.processInput(input.asChecks(), true, &resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["http.get.success"])
}

func TestWebCheckHeaders(t *testing.T) {
	// verifies that extra headers are being set in http requests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)

		assert.Equal(t, "Basic dXNlcm5hbWU6cGFzc3dvcmQ=", r.Header.Get("Authorization"))
		assert.Equal(t, "no-cache", r.Header.Get("Cache-Control"))
	}))
	defer ts.Close()

	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.HTTPCheckTimeout = 10.0
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	input := &Input{
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
	fm.processInput(input.asChecks(), true, &resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["http.get.success"])
}

func TestNormalizeURLPort(t *testing.T) {
	var urls = []struct {
		input    string
		expected string
	}{
		{"http://www.google.com:80/en/", "http://www.google.com/en/"},
		{"https://www.google.com:443/en/", "https://www.google.com/en/"},
		{"https://www.google.com:5555/en/", "https://www.google.com:5555/en/"},
	}

	for _, u := range urls {
		url, err := normalizeURLPort(u.input)
		assert.Equal(t, u.expected, url)
		assert.Equal(t, nil, err)
	}
}

func TestWebCheckPresentTextSuccess(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.HTTPCheckTimeout = 10.0
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	input := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:                 2.0,
				URL:                     "https://www.google.com",
				Method:                  "get",
				ExpectedHTTPStatus:      200,
				SearchHTMLSource:        true,
				ExpectedPattern:         "<title>Google</title>",
				ExpectedPatternPresence: "present",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(input.asChecks(), true, &resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["http.get.success"])
}

func TestWebCheckPresentTextFail(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.HTTPCheckTimeout = 10.0
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	input := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:                 2.0,
				URL:                     "https://www.google.com",
				Method:                  "get",
				ExpectedHTTPStatus:      200,
				SearchHTMLSource:        false,
				ExpectedPattern:         "yahoo rules",
				ExpectedPatternPresence: "present",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(input.asChecks(), true, &resultsChan)
	res := <-resultsChan
	require.Equal(t, "pattern expected to be present 'yahoo rules' not found in the extracted text", res.Message)
}

func TestWebCheckAbsentTextSuccess(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.HTTPCheckTimeout = 10.0
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	input := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:                 2.0,
				URL:                     "https://www.google.com",
				Method:                  "get",
				ExpectedHTTPStatus:      200,
				SearchHTMLSource:        true,
				ExpectedPattern:         "<title>Yahoo</title>",
				ExpectedPatternPresence: "absent",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(input.asChecks(), true, &resultsChan)
	res := <-resultsChan
	require.Equal(t, nil, res.Message)
	require.Equal(t, 1, res.Measurements["http.get.success"])
}

func TestWebCheckAbsentTextFail(t *testing.T) {
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	cfg.HTTPCheckTimeout = 10.0
	cfg.Sleep = 10
	fm := helperCreateFrontman(t, cfg)
	input := &Input{
		WebChecks: []WebCheck{{
			UUID: "webcheck1",
			Check: WebCheckData{
				Timeout:                 2.0,
				URL:                     "https://www.google.com",
				Method:                  "get",
				ExpectedHTTPStatus:      200,
				SearchHTMLSource:        false,
				ExpectedPattern:         "Google",
				ExpectedPatternPresence: "absent",
			},
		}},
	}
	resultsChan := make(chan Result, 100)
	fm.processInput(input.asChecks(), true, &resultsChan)
	res := <-resultsChan
	require.Equal(t, "pattern expected to be absent 'Google' found in the extracted text", res.Message)
}
