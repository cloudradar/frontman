package frontman

import (
	"encoding/json"
)

type ServiceCheckKey string
type ServiceName string

const (
	CheckTypeICMPPing ServiceCheckKey = "icmp.ping"
	CheckTypeTCP      ServiceCheckKey = "net.tcp"

	ServiceTCP ServiceName = "tcp"
)

type Input struct {
	ServiceChecks []ServiceCheck `json:"serviceChecks"`
	WebChecks     []WebCheck     `json:"webChecks"`
}

type ServiceCheck struct {
	UUID string           `json:"checkUuid"`
	Key  ServiceCheckKey  `json:"checkKey"`
	Data ServiceCheckData `json:"data"`
}

type ServiceCheckData struct {
	Connect string      `json:"connect,omitempty"`
	Service string      `json:"service,omitempty"`
	Port    json.Number `json:"port,omitempty"`
}

type WebCheck struct {
	UUID string       `json:"checkUuid"`
	Key  string       `json:"checkKey"`
	Data WebCheckData `json:"data"`
}

type WebCheckData struct {
	Method              string  `json:"method"`
	URL                 string  `json:"url"`
	ExpectedHTTPStatus  int     `json:"expectedHttpStatus,omitempty"`
	SearchHTMLSource    bool    `json:"searchHtmlSource"`
	ExpectedPattern     string  `json:"expectedPattern,omitempty"`
	DontFollowRedirects bool    `json:"dontFollowRedirects"`
	Timeout             float64 `json:"timeout"`
}

type Results struct {
	Results []Result `json:"results"`
}

type Result struct {
	CheckUUID   string `json:"checkUuid"`
	Timestamp   int64  `json:"timestamp"`
	FinalResult int    `json:"finalResult"`
	CheckKey    string `json:"checkKey"`
	CheckType   string `json:"checkType"`
	Data        struct {
		Check        interface{} `json:"check"`
		Measurements interface{} `json:"measurements"`
		Message      interface{} `json:"message"`
	} `json:"data"`
}

type MeasurementICMP struct {
	RoundTripTime ValueInUnit `json:"roundTripTime"`
	PingLoss      ValueInUnit `json:"pingLoss"`
}

type MeasurementTCP struct {
	ConnectTime ValueInUnit `json:"connectTime"`
}

type MeasurementWebcheck struct {
	TotalTimeSpent ValueInUnit `json:"totalTimeSpent"`
	HTTPStatusCode struct {
		Value int `json:"value"`
	} `json:"httpStatusCode"`
	BytesReceived       ValueIntInUnit `json:"bytesReceived"`
	DownloadPerformance ValueIntInUnit `json:"downloadPerformance"`
}

type ValueInUnit struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type ValueIntInUnit struct {
	Value int64  `json:"value"`
	Unit  string `json:"unit"`
}
