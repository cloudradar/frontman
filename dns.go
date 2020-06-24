package frontman

import (
	"fmt"
	"net"
	"time"
)

// DNS using UDP
func (fm *Frontman) runDNSUDPCheck(addr *net.TCPAddr, hostname string) (MeasurementsMap, error) {

	if addr.Port <= 0 {
		addr.Port = 53
	}

	prefix := fmt.Sprintf("net.dns.udp.%d.", addr.Port)

	m := MeasurementsMap{
		prefix + "success": 0,
	}

	started := time.Now()
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(started).Seconds()
	}()

	checkTimeout := secToDuration(fm.Config.NetUDPTimeout)

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

	err = executeUDPServiceCheck(conn.(*net.UDPConn), checkTimeout, "udp", hostname)
	if err != nil {
		return m, fmt.Errorf("failed to verify dns.udp service on %d port: %s", addr.Port, err.Error())
	}

	m[prefix+"success"] = 1
	return m, nil
}

// DNS using TCP
func (fm *Frontman) runDNSTCPCheck(addr *net.TCPAddr, hostname string) (MeasurementsMap, error) {

	if addr.Port <= 0 {
		addr.Port = 53
	}

	prefix := fmt.Sprintf("net.dns.tcp.%d.", addr.Port)

	m := MeasurementsMap{
		prefix + "success": 0,
	}

	started := time.Now()
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(started).Seconds()
	}()

	checkTimeout := secToDuration(fm.Config.NetTCPTimeout)

	conn, err := net.DialTimeout("tcp", addr.String(), checkTimeout)
	m[prefix+"connectTime_s"] = time.Since(started).Seconds()
	if err != nil {
		return m, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(checkTimeout))
	if err != nil {
		return m, fmt.Errorf("can't set TCP conn timeout: %s", err.Error())
	}

	err = executeTCPServiceCheck(conn, fm.Config.NetTCPTimeout, "tcp", hostname)
	if err != nil {
		return m, fmt.Errorf("failed to verify dns.tcp service on %d port: %s", addr.Port, err.Error())
	}

	m[prefix+"success"] = 1
	return m, nil
}
