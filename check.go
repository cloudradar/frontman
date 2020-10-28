package frontman

import (
	"encoding/json"
	"reflect"
	"sync"

	"github.com/sirupsen/logrus"
)

type Check interface {
	// run always returns a *Result, even in case of failure
	run(fm *Frontman) (*Result, error)

	// uniqueUD returns the check UUID
	uniqueID() string
}

type Input struct {
	ServiceChecks []ServiceCheck `json:"serviceChecks"`
	WebChecks     []WebCheck     `json:"webChecks"`
	SNMPChecks    []SNMPCheck    `json:"snmpChecks,omitempty"`
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

func mutexLocked(m *sync.Mutex) bool {
	const locked = 1
	state := reflect.ValueOf(m).Elem().FieldByName("state")
	return state.Int()&locked == locked
}

// used to keep track of in-progress checks being run
type inProgressChecks struct {
	mutex sync.Mutex
	uuids []string
}

func (ipc *inProgressChecks) add(uuid string) {
	logrus.Error("fm.ipc.mutex.Lock add")
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	ipc.uuids = append(ipc.uuids, uuid)
}

func (ipc *inProgressChecks) remove(uuid string) {
	logrus.Error("fm.ipc.mutex.Lock remove")
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	for i, v := range ipc.uuids {
		if v == uuid {
			ipc.uuids = append(ipc.uuids[:i], ipc.uuids[i+1:]...)
			return
		}
	}
	logrus.Errorf("inProgressChecks.remove: %v not found. len is %v", uuid, len(ipc.uuids))
}

func (ipc *inProgressChecks) isInProgress(uuid string) bool {
	logrus.Error("fm.ipc.mutex.Lock isInProgress")
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	for _, v := range ipc.uuids {
		if v == uuid {
			return true
		}
	}
	return false
}

// returns the slice index for the first check in `checks` that is not already in progress, false if none found
func (ipc *inProgressChecks) getIndexOfFirstNotInProgress(checks []Check) (int, bool) {
	for idx, c := range checks {
		if !ipc.isInProgress(c.uniqueID()) {
			return idx, true
		}
		logrus.Infof("Skipping request for check %v. Check still in progress.", c.uniqueID())
	}
	return 0, false
}
