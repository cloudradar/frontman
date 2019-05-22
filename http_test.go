package frontman

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPingHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/ping", nil)
	assert.Equal(t, nil, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(pingHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	expected := `{"alive": true}`
	assert.Equal(t, expected, rr.Body.String())
}

func TestHttpCheckHandler(t *testing.T) {
	checks := `{
		"webChecks": [{
			"checkUUID": "web_head_status_matched",
			"check": { "url": "https://www.google.com", "method": "head", "expectedHttpStatus": 200}
		  }]
	  }`

	reader := strings.NewReader(checks)
	req, err := http.NewRequest("POST", "/check", reader)
	assert.Equal(t, nil, err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(checkHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// XXX result should be json output from webChecks
	expected := `{"alive": true}`
	assert.Equal(t, expected, rr.Body.String())
}
