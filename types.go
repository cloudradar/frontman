package frontman

type CheckType string

const CheckTypeICMPPing CheckType = "icmp.ping"

type Input struct {
	ServiceChecks []ServiceCheck `json:"serviceChecks"`
}

type ServiceCheck struct {
	UUID string    `json:"checkUuid"`
	Type CheckType `json:"checkType"`
	Data struct {
		Connect string `json:"connect"`
	} `json:"data"`
}

type MeasurementICMP struct {
	RoundTripTime struct {
		Value float64 `json:"value"`
		Unit  string  `json:"unit"`
	} `json:"roundTripTime"`
	PingLoss struct {
		Value float64 `json:"value"`
		Unit  string  `json:"unit"`
	} `json:"pingLoss"`
}

type Result struct {
	CheckUUID   string `json:"checkUuid"`
	Timestamp   int64  `json:"timestamp"`
	FinalResult int    `json:"finalResult"`
	CheckKey    string `json:"checkKey"`
	CheckType   string `json:"checkType"`
	Data        struct {
		Check struct {
			Connect string `json:"connect"`
		} `json:"check"`
		Measurements interface{} `json:"measurements"`
		Message      interface{} `json:"message"`
	} `json:"data"`
}
