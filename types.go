package frontman

type ServiceName string

const (
	ProtocolICMP = "icmp"
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolSSL  = "ssl"

	ServiceICMPPing = "ping"
)

type Results struct {
	Results  []Result               `json:"results"`
	HostInfo map[string]interface{} `json:"hostInfo,omitempty"`
}

type Result struct {
	CheckUUID        string                   `json:"checkUuid"`
	Timestamp        int64                    `json:"timestamp"`
	CheckType        string                   `json:"checkType"`
	Check            interface{}              `json:"check"` // *CheckData
	Measurements     map[string]interface{}   `json:"measurements"`
	Message          interface{}              `json:"message"`
	Node             string                   `json:"node,omitempty"` // filled in when result is coming from a neighbor
	NodeMeasurements []map[string]interface{} `json:"nodeMeasurements,omitempty"`
}

type MeasurementsMap map[string]interface{}
