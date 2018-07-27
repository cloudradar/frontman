package frontman

import (
	"net"
	"time"
)

func (fm *Frontman) runTCPCheck(addr *net.TCPAddr) (m MeasurementTCP, res int, err error) {
	started := time.Now()
	conn, err := net.DialTimeout("tcp", addr.String(), secToDuration(fm.NetTCPTimeout))
	if err != nil {
		return
	}
	defer conn.Close()

	m.ConnectTime = ValueInUnit{time.Since(started).Seconds(), "s"}
	res = 1

	return
}
