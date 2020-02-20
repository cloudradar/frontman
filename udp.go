package frontman

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/cloudradar-monitoring/frontman/pkg/iax"
	"github.com/cloudradar-monitoring/frontman/pkg/utils"
)

func (fm *Frontman) runUDPCheck(addr *net.UDPAddr, hostname string, service string) (MeasurementsMap, error) {
	if addr.Port <= 0 {
		return nil, fmt.Errorf("invalid port value: %d", addr.Port)
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
		m[prefix+"connectTime_s"] = time.Since(started).Seconds()
	}()

	checkTimeout := secToDuration(fm.Config.NetUDPTimeout)

	// Open connection to the specified addr
	conn, err := net.DialTimeout("udp", addr.String(), checkTimeout)
	if err != nil {
		return m, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(checkTimeout))
	if err != nil {
		return m, fmt.Errorf("can't set UDP conn timeout: %s", err.Error())
	}

	// Execute the check
	err = executeUDPServiceCheck(conn, checkTimeout, service, hostname)
	if err != nil {
		return m, fmt.Errorf("failed to verify '%s' service on %d port: %s", service, addr.Port, err.Error())
	}

	// Mark check as successful
	m[prefix+"success"] = 1

	return m, nil
}

// executeUDPServiceCheck executes a check based on the passed protocol name on the given connection
func executeUDPServiceCheck(conn net.Conn, udpTimeout time.Duration, service, hostname string) error {
	var err error
	switch service {
	case "sip":
		err = checkSIP(conn, hostname, udpTimeout)
	case "iax2":
		err = checkIAX2(conn, udpTimeout)
	case "udp":
		// In the previous call to net.Dial the test basically already happened while establishing the connection
		// so we don't have to do anything additional here.
	default:
		err = fmt.Errorf("unknown service '%s'", service)
	}

	return err
}

func checkSIP(conn net.Conn, hostname string, timeout time.Duration) error {
	const magicCookie = "z9hG4bK" // See: https://tools.ietf.org/html/rfc3261#section-8.1.1.7

	requestStr := `OPTIONS sip:%s SIP/2.0
Accept: application/sdp
CSeq: 0 OPTIONS
Via: SIP/2.0/UDP 127.0.0.1;branch=%s
From: "frontman" <sip:frontman@127.0.0.1> ;tag=%s
To: <sip:%s>
Call-ID: frontman-%d
Content-Length: 0`

	branchIDPart := utils.RandomizedStr(11)
	fromTag := magicCookie + utils.RandomizedStr(8)
	timestamp := time.Now().Unix()

	requestStr = fmt.Sprintf(requestStr, hostname, branchIDPart, fromTag, hostname, timestamp)

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write([]byte(requestStr))
	if err != nil {
		return err
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)
	if err != nil {
		return err
	}

	expected := []byte("SIP/2")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	return nil
}

func checkIAX2(conn net.Conn, timeout time.Duration) error {
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
	// new version of Asterisk do no require this, but old
	// will resend PONG packets
	ackPacket := iax.GetAckFramePacket()
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(ackPacket)

	return nil
}
