package frontman

import (
	"runtime"
	"time"

	"github.com/go-ping/ping"

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

	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return
	}

	if CheckIfRawICMPAvailable() || runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}

	pinger.Timeout = secToDuration(fm.Config.ICMPTimeout)
	pinger.Count = 5

	pinger.Run()

	var total time.Duration

	stats := pinger.Statistics()
	for _, rtt := range stats.Rtts {
		total += rtt
	}

	if pinger.PacketsSent > 0 {
		m[prefix+"packetLoss_percent"] = float64(pinger.PacketsSent-pinger.PacketsRecv) / float64(pinger.PacketsSent) * 100
	}
	if (len(stats.Rtts)) > 0 {
		m[prefix+"roundTripTime_s"] = total.Seconds() / float64(len(stats.Rtts))
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
