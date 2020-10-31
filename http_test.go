package frontman

import (
	"encoding/json"
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

	cfg := NewConfig()
	fm := helperCreateFrontman(t, cfg)

	reader := strings.NewReader(checks)
	req, err := http.NewRequest("POST", "/check", reader)
	assert.Equal(t, nil, err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(fm.checkHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	data := rr.Body.Bytes()
	assert.Equal(t, true, len(data) > 2)

	var f interface{}
	err = json.Unmarshal(data, &f)
	assert.Equal(t, nil, err)

	dec1 := f.([]interface{})
	dec := dec1[0].(map[string]interface{})
	measurements := dec["measurements"].(map[string]interface{})

	assert.Equal(t, nil, dec["message"])
	assert.Equal(t, "webCheck", dec["checkType"])
	assert.Equal(t, "web_head_status_matched", dec["checkUuid"])
	assert.Equal(t, 200., measurements["http.head.httpStatusCode"])
	assert.Equal(t, 1., measurements["http.head.success"])
	assert.Equal(t, map[string]interface{}{
		"dontFollowRedirects": false,
		"expectedHttpStatus":  200.,
		"method":              "head",
		"searchHtmlSource":    false,
		"url":                 "https://www.google.com",
	}, dec["check"])
}

func TestHttpCheckInvalidHost(t *testing.T) {
	checks := `{
		"webChecks": [{
			"checkUUID": "webcheck_broken",
			"check": { "url": "http://notfound.site.com/", "method": "get", "expectedHttpStatus": 200}
		  }]
	  }`

	cfg := NewConfig()
	fm := helperCreateFrontman(t, cfg)

	reader := strings.NewReader(checks)
	req, err := http.NewRequest("POST", "/check", reader)
	assert.Equal(t, nil, err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(fm.checkHandler)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	data := rr.Body.Bytes()
	assert.Equal(t, true, len(data) > 2)

	var f interface{}
	err = json.Unmarshal(data, &f)
	assert.Equal(t, nil, err)

	dec1 := f.([]interface{})
	dec := dec1[0].(map[string]interface{})

	assert.NotEqual(t, nil, dec["measurements"])
	measurements := dec["measurements"].(map[string]interface{})

	assert.Equal(t, `Get "http://notfound.site.com/": dial tcp: lookup notfound.site.com: no such host`, dec["message"])
	assert.Equal(t, "webCheck", dec["checkType"])
	assert.Equal(t, "webcheck_broken", dec["checkUuid"])
	assert.Equal(t, 0., measurements["http.get.success"])
}
