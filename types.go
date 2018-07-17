package frontman

import "encoding/json"

type ServiceCheckKey string
type ServiceName string

const (
	CheckTypeICMPPing ServiceCheckKey = "icmp.ping"
	CheckTypeTCP      ServiceCheckKey = "net.tcp"

	ServiceTCP ServiceName = "tcp"
)

type Input struct {
	ServiceChecks []ServiceCheck `json:"serviceChecks"`
}

type ServiceCheck struct {
	UUID string           `json:"checkUuid"`
	Key  ServiceCheckKey  `json:"checkKey"`
	Data ServiceCheckData `json:"data"`
}

type ServiceCheckData struct {
	Connect string      `json:",omitempty"`
	Service string      `json:",omitempty"`
	Port    json.Number `json:",omitempty"`
}

type MeasurementICMP struct {
	RoundTripTime ValueInUnit `json:"roundTripTime"`
	PingLoss      ValueInUnit `json:"pingLoss"`
}

type ValueInUnit struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type MeasurementTCP struct {
	ConnectTime ValueInUnit `json:"connectTime"`
}

type Result struct {
	CheckUUID   string `json:"checkUuid"`
	Timestamp   int64  `json:"timestamp"`
	FinalResult int    `json:"finalResult"`
	CheckKey    string `json:"checkKey"`
	CheckType   string `json:"checkType"`
	Data        struct {
		Check        ServiceCheckData `json:"check"`
		Measurements interface{}      `json:"measurements"`
		Message      interface{}      `json:"message"`
	} `json:"data"`
}
