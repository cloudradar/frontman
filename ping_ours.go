package frontman

import (
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

func (fm *Frontman) runPing(addr string) (m map[string]interface{}, err error) {
	prefix := "net.icmp.ping."
	m = make(map[string]interface{})

	pinger, err := NewPinger(addr)

	if CheckIfRawICMPAvailable() || runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}

	if err != nil {
		return
	}

	pinger.Timeout = secToDuration(fm.Config.ICMPTimeout)
	pinger.Count = 5

	pinger.run()

	var total time.Duration
	for _, rtt := range pinger.rtts {
		total += rtt
	}

	if pinger.PacketsSent > 0 {
		m[prefix+"packetLoss_percent"] = float64(pinger.PacketsSent-pinger.PacketsRecv) / float64(pinger.PacketsSent) * 100
	}
	if (len(pinger.rtts)) > 0 {
		m[prefix+"roundTripTime_s"] = total.Seconds() / float64(len(pinger.rtts))
	}
	success := 0
	if pinger.PacketsRecv > 0 {
		success = 1
	} else {
		err = errors.New("no packets received")
	}

	m[prefix+"success"] = success

	return
}
