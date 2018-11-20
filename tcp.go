package frontman

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"gopkg.in/ldap.v2"
)

var defaultPortByService = map[string]int{
	"ftp":   21,
	"ftps":  990,
	"http":  80,
	"https": 443,
	"imap":  143,
	"imaps": 993,
	"ldap":  389,
	"ldaps": 636,
	"nntp":  119,
	"pop3":  110,
	"pop3s": 995,
	"smtp":  25,
	"smtps": 465,
	"ssh":   22,
}

var errorFailedToVerifyService = errors.New("Failed to verify service")

func (fm *Frontman) runTCPCheck(addr *net.TCPAddr, hostname string, service string) (MeasurementsMap, error) {
	service = strings.ToLower(service)

	// Check if we have to autodetect port by service name
	if addr.Port <= 0 {
		// Lookup service by default port
		port, exists := defaultPortByService[service]
		if !exists {
			return nil, fmt.Errorf("failed to auto-determine port for '%s'", service)
		}
		addr.Port = port
	}

	prefix := fmt.Sprintf("net.tcp.%s.%d.", service, addr.Port)

	// Initialise MeasurementsMap
	m := MeasurementsMap{
		prefix + "success": 0,
	}

	// Start measuring execution time
	started := time.Now()

	// Open connection to the specified addr
	conn, err := net.DialTimeout("tcp", addr.String(), secToDuration(fm.NetTCPTimeout))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Execute the check
	err = fm.executeCheck(conn, service, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to verify '%s' service on %d port: %s", service, addr.Port, err.Error())
	}

	// Stop measuring execution time
	m[prefix+"connectTime_s"] = time.Since(started).Seconds()
	m[prefix+"success"] = 1

	return m, nil
}

// executeCheck executes the check based on the passed service name
func (fm *Frontman) executeCheck(conn net.Conn, service, hostname string) error {
	var err error
	switch service {
	case "ftp":
		err = checkFTP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "ftps":
		err = checkFTPS(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "imap":
		err = checkIMAP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "imaps":
		err = checkIMAPS(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "smtp":
		err = checkSMTP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "smtps":
		err = checkSMTPS(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "pop3":
		err = checkPOP3(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "pop3s":
		err = checkPOP3S(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "ssh":
		err = checkSSH(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "nntp":
		err = checkNNTP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "ldap":
		err = checkLDAP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "ldaps":
		err = checkLDAPS(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "http":
		err = checkHTTP(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "https":
		err = checkHTTPS(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "tcp":
		// In the previous call to net.Dial the test basically already happened while establishing the connection
		// so we don't have to do anything additional here.
		break
	default:
		err = fmt.Errorf("unknown service '%s'", service)
	}

	return err
}

func checkNNTP(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("200")
	expected2 := []byte("201")

	if !bytes.HasPrefix(b, expected) && !bytes.HasPrefix(b, expected2) {
		return fmt.Errorf("invalid response: expected to start with '%s' or '%s' but got '%s'", string(expected), string(expected2), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
}

func checkPOP3(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("+OK")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
}

func checkPOP3S(conn net.Conn, hostname string, timeout time.Duration) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"pop3"}})

	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return checkPOP3(tlsConn, timeout)
}

var sshHelloRegex = regexp.MustCompile(`^SSH-[0-9]+\.[0-9]+-.*?\r?\n?`)

func checkSSH(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 512)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	if !sshHelloRegex.Match(b) {
		return fmt.Errorf("invalid response: expected to match '%s' but got '%s'", sshHelloRegex.String(), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("SSH-1.0-frontman\r\n"))

	return err
}

func checkSMTP(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("220")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
}

func checkSMTPS(conn net.Conn, hostname string, timeout time.Duration) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"smtp"}})

	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return checkSMTP(tlsConn, timeout)
}

func checkIMAP(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("* OK")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("a1 LOGOUT\r\n"))

	return err
}

func checkIMAPS(conn net.Conn, hostname string, timeout time.Duration) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"imap"}})

	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return checkIMAP(tlsConn, timeout)
}

func checkFTP(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("220")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
}

func checkFTPS(conn net.Conn, hostname string, timeout time.Duration) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"ftp"}})

	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return checkFTP(tlsConn, timeout)
}

func checkHTTP(conn net.Conn, hostname string, timeout time.Duration) error {
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write([]byte(fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname)))
	if err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("HTTP/1")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	return nil
}

func checkHTTPS(conn net.Conn, hostname string, timeout time.Duration) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})

	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return checkHTTP(tlsConn, hostname, timeout)
}

func checkLDAP(conn net.Conn, timeout time.Duration) error {
	ldapConn := ldap.NewConn(conn, false)
	ldapConn.SetTimeout(timeout)

	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, int(timeout.Seconds()+0.5), false,
		"(objectClass=*)",    // The filter to apply
		[]string{"dn", "cn"}, // A list attributes to retrieve
		nil,
	)

	ldapConn.Start()
	defer ldapConn.Close()

	sr, err := ldapConn.SearchWithPaging(searchRequest, 1)
	if err != nil {
		return err
	}

	if len(sr.Entries) == 0 {
		return errors.New("no entries found")
	}

	return nil
}

func checkLDAPS(conn net.Conn, hostname string, timeout time.Duration) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"ldap"}})

	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return checkLDAP(tlsConn, timeout)
}
