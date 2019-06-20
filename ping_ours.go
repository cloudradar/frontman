package frontman

import (
	"net"
	"runtime"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
)

func CheckIfRawICMPAvailable() bool {
	conn, err := icmp.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

func CheckIfRootlessICMPAvailable() bool {
	conn, err := icmp.ListenPacket("udp4", "")
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

func (fm *Frontman) runPing(addr *net.IPAddr) (m map[string]interface{}, err error) {
	prefix := "net.icmp.ping."
	m = make(map[string]interface{})

	p, err := NewPinger(addr.String())

	if CheckIfRawICMPAvailable() || runtime.GOOS == "windows" {
		p.SetPrivileged(true)
	}

	if err != nil {
		return
	}

	p.Timeout = secToDuration(fm.Config.ICMPTimeout)
	p.Count = 5

	p.run()

	var total time.Duration
	for _, rtt := range p.rtts {
		total += rtt
	}

	if p.PacketsSent > 0 {
		m[prefix+"packetLoss_percent"] = float64(p.PacketsSent-p.PacketsRecv) / float64(p.PacketsSent) * 100
	}
	if (len(p.rtts)) > 0 {
		m[prefix+"roundTripTime_s"] = total.Seconds() / float64(len(p.rtts))
	}
	success := 0
	if p.PacketsRecv > 0 {
		success = 1
	} else {
		err = errors.New("no packets received")
	}

	m[prefix+"success"] = success

	return
}
