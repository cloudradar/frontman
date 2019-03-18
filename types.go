package frontman

import (
	"encoding/json"
)

type ServiceName string

const (
	ProtocolICMP = "icmp"
	ProtocolTCP  = "tcp"
	ProtocolSSL  = "ssl"

	ServiceICMPPing = "ping"
)

type Input struct {
	ServiceChecks []ServiceCheck `json:"serviceChecks"`
	WebChecks     []WebCheck     `json:"webChecks"`
}

type ServiceCheck struct {
	UUID  string           `json:"checkUuid"`
	Check ServiceCheckData `json:"check"`
}

type ServiceCheckData struct {
	Connect  string      `json:"connect,omitempty"`
	Service  string      `json:"service,omitempty"`
	Protocol string      `json:"protocol,omitempty"`
	Port     json.Number `json:"port,omitempty"`
}

type WebCheck struct {
	UUID  string       `json:"checkUuid"`
	Check WebCheckData `json:"check"`
}

type WebCheckData struct {
	Method              string  `json:"method"`
	URL                 string  `json:"url"`
	PostData            string  `json:"postData,omitempty"`
	ExpectedHTTPStatus  int     `json:"expectedHttpStatus,omitempty"`
	SearchHTMLSource    bool    `json:"searchHtmlSource"`
	ExpectedPattern     string  `json:"expectedPattern,omitempty"`
	DontFollowRedirects bool    `json:"dontFollowRedirects"`
	IgnoreSSLErrors     bool    `json:"ignoreSSLErrors,omitempty"`
	Timeout             float64 `json:"timeout,omitempty"`
}

type Results struct {
	Results  []Result               `json:"results"`
	HostInfo map[string]interface{} `json:"hostInfo,omitempty"`
}

type Result struct {
	CheckUUID    string                 `json:"checkUuid"`
	Timestamp    int64                  `json:"timestamp"`
	CheckType    string                 `json:"checkType"`
	Check        interface{}            `json:"check"`
	Measurements map[string]interface{} `json:"measurements"`
	Message      interface{}            `json:"message"`
}

type MeasurementsMap map[string]interface{}
