package frontman

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"runtime"
)

const (
	timeSliceLength  = 8
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// NewPinger returns a new Pinger struct pointer
func NewPinger(addr *net.IPAddr) (*Pinger, error) {
	return &Pinger{
		ipaddr:  addr,
		source: "0.0.0.0",
		Timeout: time.Second * 4,
		Count:   -1,

		network: "udp",
		size:    timeSliceLength,

		done: make(chan bool),
	}, nil
}

// Pinger represents ICMP packet sender/receiver
type Pinger struct {
	// ICMP packet timeout
	Timeout time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// stop chan bool
	done chan bool

	ipaddr *net.IPAddr

	source   string
	size     int
	sequence int
	network  string
}

func (p *Pinger) isIPv4() bool {
	return len(p.ipaddr.IP.To4()) == net.IPv4len
}

func (p *Pinger) isIPv6() bool {
	return len(p.ipaddr.IP) == net.IPv6len
}

type packet struct {
	bytes  []byte
	nbytes int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int
}

// SetPrivileged sets the type of ping pinger will send.
// false means pinger will send an "unprivileged" UDP ping.
// true means pinger will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *Pinger) SetPrivileged(privileged bool) {
	if privileged {
		p.network = "ip"
	} else {
		p.network = "udp"
	}
}

func (p *Pinger) run() {
	var conn *icmp.PacketConn
	if p.isIPv4() {
		if conn = p.listen(ipv4Proto[p.network], p.source); conn == nil {
			return
		}
	} else {
		if conn = p.listen(ipv6Proto[p.network], p.source); conn == nil {
			return
		}
	}
	defer conn.Close()

	var wg sync.WaitGroup
	recv := make(chan *packet, 5)
	wg.Add(1)
	go p.recvICMP(conn, recv, &wg)

	for {
		err := p.sendICMP(conn)
		if err != nil {
			log.Errorf("#%d ICMP send error: %s", p.sequence, err.Error())
			continue
		}
		timeout := time.NewTimer(p.Timeout)
		wg.Add(1)

		select {
		case <-p.done:
			wg.Wait()
			return
		case <-timeout.C:
			log.Debugf("#%d %s timeouted", p.sequence, p.ipaddr.String())

			wg.Done()
			timeout = time.NewTimer(p.Timeout)

		case r := <-recv:
			wg.Done()
			err := p.processPacket(r)
			if err != nil {
				log.Errorf("#%d %s: %s", p.sequence, p.ipaddr.IP, err.Error())
			}
		}

		if p.Count > 0 && p.PacketsSent >= p.Count {
			close(p.done)
			wg.Wait()
			return
		}
	}
}

func (p *Pinger) recvICMP(
	conn *icmp.PacketConn,
	recv chan<- *packet,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for {
		select {
		case <-p.done:
			return
		default:
			bytes := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			n, _, err := conn.ReadFrom(bytes)
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						continue
					} else {
						close(p.done)
						return
					}
				}
			}

			recv <- &packet{bytes: bytes, nbytes: n}
		}
	}
}

func (p *Pinger) processPacket(recv *packet) error {
	var bytes []byte
	var proto int
	if p.isIPv4() {
		if p.network == "ip" {
			bytes = ipv4Payload(recv.bytes)
		} else {
			bytes = recv.bytes
		}
		proto = protocolICMP
	} else {
		bytes = recv.bytes
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, bytes[:recv.nbytes]); err != nil {
		return fmt.Errorf("Error parsing icmp message")
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		return nil
	}

	outPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.ipaddr,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		outPkt.Rtt = time.Since(bytesToTime(pkt.Data[:timeSliceLength]))
		outPkt.Seq = pkt.Seq
		p.PacketsRecv += 1
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("Error, invalid ICMP echo reply. Body type: %T, %s",
			pkt, pkt)
	}

	p.rtts = append(p.rtts, outPkt.Rtt)
	handler := p.OnRecv
	if handler != nil {
		handler(outPkt)
	}

	return nil
}

func (p *Pinger) sendICMP(conn *icmp.PacketConn) error {
	var typ icmp.Type
	if p.isIPv4() {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = p.ipaddr
	if p.network == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	t := timeToBytes(time.Now())
	if p.size-timeSliceLength != 0 {
		t = append(t, byteSliceOfSize(p.size-timeSliceLength)...)
	}
	bytes, err := (&icmp.Message{
		Type: typ, Code: 0,
		Body: &icmp.Echo{
			ID:   rand.Intn(65535),
			Seq:  p.sequence,
			Data: t,
		},
	}).Marshal(nil)
	if err != nil {
		return err
	}

	for {
		if _, err := conn.WriteTo(bytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		p.PacketsSent += 1
		p.sequence += 1
		break
	}
	return nil
}

func (p *Pinger) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		log.Errorf("Error listening for ICMP packets: %s", err.Error())
		close(p.done)
		return nil
	}
	return conn
}

func CheckIfRawICMPAvailable() bool {
	conn, err := icmp.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

func CheckIfRootlessICMPAvailable() bool {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = 1
	}

	return b
}

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func (fm *Frontman) runPing(addr *net.IPAddr) (m MeasurementICMP, finalResult int, err error) {

	p, err := NewPinger(addr)

	if CheckIfRawICMPAvailable()  || runtime.GOOS == "windows" {
		p.SetPrivileged(true)
	}

	if err != nil {
		return
	}

	p.Timeout = secToDuration(fm.ICMPTimeout)
	p.Count = 5

	p.run()

	var total time.Duration
	for _, rtt := range p.rtts {
		total += rtt
	}

	m.PingLoss = ValueInUnit{float64(p.PacketsSent-p.PacketsRecv) / float64(p.PacketsSent) * 100, "%"}

	if len(p.rtts) > 0 {
		m.RoundTripTime = ValueInUnit{total.Seconds() / float64(len(p.rtts)), "s"}
	}

	if p.PacketsRecv > 0 {
		finalResult = 1
	}

	return
}
