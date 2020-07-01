package frontman

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/cloudradar-monitoring/frontman/pkg/iax"
	"github.com/cloudradar-monitoring/frontman/pkg/utils"
)

func (fm *Frontman) runUDPCheck(addr *net.UDPAddr, hostname string, service string) (MeasurementsMap, error) {
	// Check if we have to autodetect port by service name
	if addr.Port <= 0 {
		// Lookup service by default port
		port, exists := defaultPortByService[service]
		if !exists {
			return nil, fmt.Errorf("failed to auto-determine port for '%s'", service)
		}
		addr.Port = port
	}

	prefix := fmt.Sprintf("net.udp.%s.%d.", service, addr.Port)

	// Initialise MeasurementsMap
	m := MeasurementsMap{
		prefix + "success": 0,
	}

	// Start measuring execution time
	started := time.Now()
	// Calculate execution time in the end
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(started).Seconds()
	}()

	checkTimeout := secToDuration(fm.Config.NetUDPTimeout)

	// Open connection to the specified addr
	conn, err := net.DialTimeout("udp", addr.String(), checkTimeout)
	m[prefix+"connectTime_s"] = time.Since(started).Seconds()
	if err != nil {
		return m, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(checkTimeout))
	if err != nil {
		return m, fmt.Errorf("can't set UDP conn timeout: %s", err.Error())
	}

	// Execute the check
	err = executeUDPServiceCheck(conn.(*net.UDPConn), checkTimeout, service, hostname)
	if err != nil {
		return m, fmt.Errorf("failed to verify '%s' service on %d port: %s", service, addr.Port, err.Error())
	}

	// Mark check as successful
	m[prefix+"success"] = 1

	return m, nil
}

// executeUDPServiceCheck executes a check based on the passed protocol name on the given connection
func executeUDPServiceCheck(conn *net.UDPConn, udpTimeout time.Duration, service, hostname string) error {
	var err error
	switch service {
	case "sip":
		err = checkSIP(conn, hostname, udpTimeout)
	case "iax2":
		err = checkIAX2(conn, udpTimeout)
	case "dns":
		// minimal DNS test just verifies connection is established
	case "udp":
		// In the previous call to net.Dial the test basically already happened while establishing the connection
		// so we don't have to do anything additional here.
	default:
		err = fmt.Errorf("unknown service '%s'", service)
	}

	return err
}

func checkSIP(conn *net.UDPConn, hostname string, timeout time.Duration) error {
	const magicCookie = "z9hG4bK" // See: https://tools.ietf.org/html/rfc3261#section-8.1.1.7

	requestTemplateText := `OPTIONS sip:{{.FromUser}}@{{.Domain}} SIP/2.0
Via: SIP/2.0/UDP {{.ContactDomain}}:{{.LPort}};branch={{.Branch}}
From: {{.FromName}} <sip:{{.FromUser}}@{{.Domain}}>;tag=0c26cd11
To: {{.FromName}} <sip:{{.ToUser}}@{{.Domain}}>
Contact: <sip:{{.FromUser}}@{{.ContactDomain}}:{{.LPort}};transport=udp>
Call-ID: {{.CallId}}
CSeq: 1 OPTIONS
User-Agent: {{.UserAgent}}
Max-Forwards: 70
Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE
Content-Length: 0

`
	requestTemplateText = strings.ReplaceAll(requestTemplateText, "\n", "\r\n")
	requestTpl, err := template.New("request").Parse(requestTemplateText)
	if err != nil {
		return err
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	params := map[string]string{
		"FromUser":      "100",
		"Domain":        hostname,
		"ContactDomain": "1.1.1.1",
		"LPort":         strconv.Itoa(localAddr.Port),
		"Branch":        magicCookie + utils.RandomizedStr(64),
		"FromName":      "",
		"ToUser":        "100",
		"CallId":        utils.RandomizedStr(32),
		"UserAgent":     "frontman",
	}
	requestBuf := bytes.NewBuffer([]byte{})
	err = requestTpl.Execute(requestBuf, params)
	if err != nil {
		return err
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = io.Copy(conn, requestBuf)
	if err != nil {
		return err
	}

	var response = make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := conn.ReadFrom(response)
	if err != nil {
		return err
	}

	expected := []byte("SIP/2")
	if !bytes.HasPrefix(response, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(response[0:n]))
	}

	return nil
}

func checkIAX2(conn *net.UDPConn, timeout time.Duration) error {
	pokePacket := iax.GetPokeFramePacket()

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(pokePacket)
	if err != nil {
		return err
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 128)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}

	if !iax.IsPongResponse(b) {
		return fmt.Errorf("invalid response to POKE request. Received bytes: %v", b)
	}

	// send ACK to close connection
	// new version of Asterisk do not require this,
	// but old will resend PONG packets
	ackPacket := iax.GetAckFramePacket()
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(ackPacket)

	return nil
}
