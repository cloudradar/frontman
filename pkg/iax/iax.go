package iax

/* IAX packet structure:
struct ast_iax2_full_hdr {
	unsigned short scallno;	// Source call number -- high bit must be 1
	unsigned short dcallno;	// Destination call number -- high bit is 1 if retransmission
	unsigned int ts;		// 32-bit timestamp in milliseconds (from 1st transmission)
	unsigned char oseqno;	// Packet number (outgoing)
	unsigned char iseqno;	// Packet number (next incoming expected)
	unsigned char type;		// Frame type
	unsigned char csub;		// Compressed subclass
	unsigned char iedata[0];
} __attribute__ ((__packed__));
*/

const minFrameLen = 12

const (
	frameTypeIAX = 0x06
	subclassPoke = 0x1e // POKE message (similar to PING but doesn't require active connection)
	subclassPong = 0x03 // PONG
	subclassAck  = 0x04 // ACK
)

var frameHeaderIAX2Full = []byte{0x80, 0x0}

func GetPokeFramePacket() []byte {
	// transforming golang structure to packed in-memory struct is pretty hard
	// so we will just construct the required packet manually
	var sCallNo = frameHeaderIAX2Full
	var dCallNo = []byte{0x0, 0x0}
	var ts = []byte{0x0, 0x0, 0x0, 0x0}
	var oSeqNo byte
	var iSeqNo byte
	var frameType byte = frameTypeIAX
	var cSub byte = subclassPoke

	var packet []byte
	packet = append(packet, sCallNo...)
	packet = append(packet, dCallNo...)
	packet = append(packet, ts...)
	packet = append(packet, oSeqNo, iSeqNo, frameType, cSub)

	return packet
}

func GetAckFramePacket() []byte {
	result := GetPokeFramePacket()
	result[11] = subclassAck
	return result
}

func IsPongResponse(frameBytes []byte) bool {
	if len(frameBytes) < minFrameLen {
		return false
	}

	var frameType = frameBytes[10]
	var cSub = frameBytes[11]

	return frameType == frameTypeIAX && cSub == subclassPong
}
