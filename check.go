package frontman

import "encoding/json"

type Check interface {
	run(fm *Frontman) (*Result, error)
}

type Input struct {
	ServiceChecks []ServiceCheck `json:"serviceChecks"`
	WebChecks     []WebCheck     `json:"webChecks"`
	SNMPChecks    []SNMPCheck    `json:"snmpChecks"`
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
	Method                  string            `json:"method"`
	URL                     string            `json:"url"`
	PostData                string            `json:"postData,omitempty"`
	ExpectedHTTPStatus      int               `json:"expectedHttpStatus,omitempty"`
	SearchHTMLSource        bool              `json:"searchHtmlSource"`
	ExpectedPattern         string            `json:"expectedPattern,omitempty"`
	ExpectedPatternPresence string            `json:"expectedPatternPresence,omitempty"`
	DontFollowRedirects     bool              `json:"dontFollowRedirects"`
	IgnoreSSLErrors         *bool             `json:"ignoreSSLErrors,omitempty"`
	Timeout                 float64           `json:"timeout,omitempty"`
	Headers                 map[string]string `json:"headers,omitempty"`
}

type SNMPCheck struct {
	UUID  string        `json:"checkUuid"`
	Check SNMPCheckData `json:"check"`
}

type SNMPCheckData struct {
	Connect                string   `json:"connect"`
	Port                   uint16   `json:"port"`
	Timeout                float64  `json:"timeout"`
	Protocol               string   `json:"protocol"`
	Community              string   `json:"community,omitempty"` // v1, v2
	Preset                 string   `json:"preset"`
	Oids                   []string `json:"oids,omitempty"`
	SecurityLevel          string   `json:"security_level,omitempty"`          // v3
	Username               string   `json:"username,omitempty"`                // v3
	AuthenticationProtocol string   `json:"authentication_protocol,omitempty"` // v3
	AuthenticationPassword string   `json:"authentication_password,omitempty"` // v3
	PrivacyProtocol        string   `json:"privacy_protocol,omitempty"`        // v3
	PrivacyPassword        string   `json:"privacy_password,omitempty"`        // v3

	// values used by "oid" preset
	Oid       string `json:"oid,omitempty"`
	Name      string `json:"name,omitempty"`
	ValueType string `json:"value_type,omitempty"` /// auto (default), hex, delta, delta_per_sec
	Unit      string `json:"unit,omitempty"`
}
