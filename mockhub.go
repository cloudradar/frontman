package frontman

// a mock hub used in tests, similar to https://bitbucket.org/cloudradar/debug_hub/

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
)

type MockHub struct {
}

func NewMockHub() *MockHub {
	return &MockHub{}
}

// returns some mocked checks
func (hub *MockHub) indexHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		hub.getHandler(w, r)
	case "POST":
		hub.postHandler(w, r)
	}
}

func (hub *MockHub) postHandler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("post got data", data)
}

func (hub *MockHub) getHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query()
	serviceChecksS := query.Get("serviceChecks")
	webChecksS := query.Get("webChecks")

	serviceChecks, err := strconv.ParseInt(serviceChecksS, 10, 64)
	if err != nil {
		serviceChecks = 5
	}

	webChecks, err := strconv.ParseInt(webChecksS, 10, 64)
	if err != nil {
		webChecks = 5
	}

	log.Println("responding with", serviceChecks, "serviceChecks", webChecks, "webChecks")

	checks := Input{
		ServiceChecks: mockServiceChecks(int(serviceChecks)),
		WebChecks:     mockWebChecks(int(webChecks)),
	}

	data, _ := json.Marshal(checks)
	w.Write(data)
}

func (hub *MockHub) Serve() {

	var listenAddr = "localhost:9100"

	http.HandleFunc("/", hub.indexHandler)

	log.Println("mock hub listening at", "http://"+listenAddr)
	http.ListenAndServe(listenAddr, nil)
}

func mockServiceChecks(n int) []ServiceCheck {
	res := []ServiceCheck{}
	for i := 0; i < n; i++ {
		res = append(res, randomServiceCheck())
	}
	return res
}

func mockWebChecks(n int) []WebCheck {
	res := []WebCheck{}
	for i := 0; i < n; i++ {
		if i%5 == 0 {
			// every fifth web check should be a lame web check
			res = append(res, lameWebCheck())
		} else {
			res = append(res, randomWebCheck())
		}
	}
	return res
}

func randomWebCheck() WebCheck {
	methods := []string{"get", "post", "head"}
	statuses := []int{200, 404}
	patterns := []string{"running", "welcome", "yyy"}
	return WebCheck{
		UUID: randomUUID(),
		Check: WebCheckData{
			URL:                fmt.Sprintf("https://h%d.hostgum.eu/", rand.Intn(1000)),
			Method:             methods[rand.Intn(len(methods))],
			ExpectedHTTPStatus: statuses[rand.Intn(len(statuses))],
			ExpectedPattern:    patterns[rand.Intn(len(patterns))],
		},
	}
}

func lameWebCheck() WebCheck {
	return WebCheck{
		UUID: randomUUID(),
		Check: WebCheckData{
			URL:                fmt.Sprintf("https://h1.hostgum.eu/sleep.php?t=%d", 5+rand.Intn(45)),
			Method:             "get",
			ExpectedHTTPStatus: 200,
			ExpectedPattern:    "slept",
			Timeout:            randomFloat(30, 60),
		},
	}
}

func randomFloat(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randomServiceCheck() ServiceCheck {
	switch rand.Intn(2) {
	case 0:
		return randomPingCheck()
	default:
		return randomTcpCheck()
	}
}

func randomPingCheck() ServiceCheck {
	return ServiceCheck{
		UUID: randomUUID(),
		Check: ServiceCheckData{
			Connect:  randomConnect(),
			Service:  "ping",
			Protocol: "icmp",
		},
	}
}

func randomTcpCheck() ServiceCheck {
	services := []string{
		"http",
		"https",
		"pop3",
		"imap",
		"smtp",
	}
	return ServiceCheck{
		UUID: randomUUID(),
		Check: ServiceCheckData{
			Connect:  fmt.Sprintf("h%d.hostgum.eu", rand.Intn(1000)),
			Protocol: "tcp",
			Service:  services[rand.Intn(len(services))],
		},
	}
}

func randomConnect() string {
	pool := []string{
		"www.google.com",
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
		"h1.hostgum.eu",
		"lameduck.hostgum.eu",
		"not_exists_domain1234.com",
		"github.com",
		"dns.google",
		"1.11.192.227",
		"202.181.242.131",
		"45.225.123.88",
		"212.91.32.6",
		"ns1.artechinfo.in",
		"pb6abf7bd.szokff01.ap.so-net.ne.jp",
		"211.105.7.5",
		"dns.prhs.ptc.edu.tw",
		"163.24.162.3",
	}
	return pool[rand.Intn(len(pool))]
}
