package frontman

import (
	"fmt"
	"net"
	"time"
)

func (fm *Frontman) runTCPCheck(addr *net.TCPAddr) (m map[string]interface{}, err error) {
	m = make(map[string]interface{})
	prefix := fmt.Sprintf("net.tcp.tcp.%d.", addr.Port)

	started := time.Now()

	conn, err := net.DialTimeout("tcp", addr.String(), secToDuration(fm.NetTCPTimeout))
	if err != nil {
		m[prefix+"success"] = 0
		return
	}
	defer conn.Close()

	m[prefix+"connectTime_s"] = time.Since(started).Seconds()
	m[prefix+"success"] = 1

	return
}
