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
	"http":  80,
	"https": 443,
	"imap":  143,
	"ldap":  389,
	"nntp":  119,
	"pop":   110,
	"smtp":  25,
	"ssh":   22,
}

var errorFailedToVerifyService = errors.New("Failed to verify service")

func (fm *Frontman) runTCPCheck(addr *net.TCPAddr, hostname string, service string) (m map[string]interface{}, err error) {
	prefix := fmt.Sprintf("net.tcp.tcp.%d.", addr.Port)
	m = MeasurementsMap{
		prefix + "success": 0,
	}
	service = strings.ToLower(service)

	if addr.Port <= 0 {
		if v, exists := defaultPortByService[service]; exists {
			addr.Port = v
		} else {
			err = fmt.Errorf("No default port specified for '%s'", service)
			return
		}
	}

	started := time.Now()

	conn, err := net.DialTimeout("tcp", addr.String(), secToDuration(fm.NetTCPTimeout))
	if err != nil {
		return
	}

	defer conn.Close()

	switch service {
	case "ftp":
		err = checkFTP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "imap":
		err = checkIMAP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "smtp":
		err = checkSMTP(conn, secToDuration(fm.NetTCPTimeout))
		break
	case "pop":
		err = checkPOP(conn, secToDuration(fm.NetTCPTimeout))
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
	case "http":
		err = checkHTTP(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "https":
		err = checkHTTPS(conn, hostname, secToDuration(fm.NetTCPTimeout))
		break
	case "tcp":
		break
	default:
		err = fmt.Errorf("Unknown service '%s'", service)
	}

	m[prefix+"connectTime_s"] = time.Since(started).Seconds()
	if err == nil {
		m[prefix+"success"] = 1
	} else {
		err = fmt.Errorf("Failed to verify '%s' service on %d port: %s", service, addr.Port, err.Error())
	}

	return
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
		return fmt.Errorf("Invalid response: expected to start with '%s' or '%s' but got '%s'", string(expected), string(expected2), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
}

func checkPOP(conn net.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var b = make([]byte, 64)
	n, err := conn.Read(b)

	if err != nil {
		return err
	}

	expected := []byte("+OK")

	if !bytes.HasPrefix(b, expected) {
		return fmt.Errorf("Invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
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
		return fmt.Errorf("Invalid response: expected to match '%s' but got '%s'", sshHelloRegex.String(), string(b[0:n]))
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
		return fmt.Errorf("Invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
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
		return fmt.Errorf("Invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("a1 LOGOUT\r\n"))

	return err
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
		return fmt.Errorf("Invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("QUIT\r\n"))

	return err
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
		return fmt.Errorf("Invalid response: expected to start with '%s' but got '%s'", string(expected), string(b[0:n]))
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
		return errors.New("No entries found")
	}

	return nil
}
