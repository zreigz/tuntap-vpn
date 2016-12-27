package vpn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	HOP_REQ uint8 = 0x20
	HOP_ACK uint8 = 0xAC
	HOP_DAT uint8 = 0xDA

	HOP_FLG_PSH byte = 0x80 // port knocking and heartbeat
	HOP_FLG_HSH byte = 0x40 // handshaking
	HOP_FLG_FIN byte = 0x20 // finish session
	HOP_FLG_MFR byte = 0x08 // more fragments
	HOP_FLG_ACK byte = 0x04 // acknowledge
	HOP_FLG_DAT byte = 0x00 // acknowledge

	HOP_STAT_INIT int32 = iota // initing
	HOP_STAT_HANDSHAKE              // handeshaking
	HOP_STAT_WORKING                // working
	HOP_STAT_FIN                    // finishing

	HOP_HDR_LEN int = 16

	HOP_PROTO_VERSION byte = 0x01 // protocol version
)

type vpnPacketHeader struct {
	Flag       byte
	Seq        uint32
	Plen       uint16
	FragPrefix uint16
	Frag       uint8
	Sid        uint32
	Dlen       uint16
}

func (p vpnPacketHeader) String() string {
	flag := make([]string, 0, 8)
	if (p.Flag ^ HOP_FLG_MFR == 0) || (p.Flag == 0) {
		flag = append(flag, "DAT")
	}
	if p.Flag & HOP_FLG_PSH != 0 {
		flag = append(flag, "PSH")
	}
	if p.Flag & HOP_FLG_HSH != 0 {
		flag = append(flag, "HSH")
	}
	if p.Flag & HOP_FLG_FIN != 0 {
		flag = append(flag, "FIN")
	}
	if p.Flag & HOP_FLG_ACK != 0 {
		flag = append(flag, "ACK")
	}
	if p.Flag & HOP_FLG_MFR != 0 {
		flag = append(flag, "MFR")
	}

	sflag := strings.Join(flag, " | ")
	return fmt.Sprintf(
		"{Flag: %s, Seq: %d, Plen: %d, Prefix: %d, Frag: %d, Dlen: %d}",
		sflag, p.Seq, p.Plen, p.FragPrefix, p.Frag, p.Dlen,
	)
}

type VpnPacket struct {
	vpnPacketHeader
	payload []byte
	noise   []byte
	buf     []byte
}

func (p *VpnPacket) Pack() []byte {
	p.Dlen = uint16(len(p.payload))
	var buf *bytes.Buffer
	if p.buf != nil {
		// reduce memcopy
		buf = bytes.NewBuffer(p.buf[:0])
		binary.Write(buf, binary.BigEndian, p.vpnPacketHeader)
	} else {
		buf = bytes.NewBuffer(make([]byte, 0, p.Size()))
		binary.Write(buf, binary.BigEndian, p.vpnPacketHeader)
		buf.Write(p.payload)
		buf.Write(p.noise)
		p.buf = buf.Bytes()
	}
	return p.buf
}

func (p *VpnPacket) Size() int {
	return HOP_HDR_LEN + len(p.payload) + len(p.noise)
}

func (p *VpnPacket) setPayload(d []byte) {
	p.payload = d
	p.Dlen = uint16(len(p.payload))
}

func (p *VpnPacket) addNoise(n int) {
	if p.buf != nil {
		s := HOP_HDR_LEN + len(p.payload)
		p.noise = p.buf[s:len(p.buf)]
	} else {
		p.noise = make([]byte, n)
	}
	rand.Read(p.noise)
}

func (p *VpnPacket) setSid(sid [4]byte) {
	p.Sid = binary.BigEndian.Uint32(sid[:])
}

func (p *VpnPacket) String() string {
	return fmt.Sprintf(
		"{%v, Payload: %v, Noise: %v}",
		p.vpnPacketHeader, p.payload, p.noise,
	)
}

func unpackHopPacket(b []byte) (*VpnPacket) {

	buf := bytes.NewBuffer(b)

	p := new(VpnPacket)
	binary.Read(buf, binary.BigEndian, &p.vpnPacketHeader)
	p.payload = make([]byte, p.Dlen)
	buf.Read(p.payload)
	return p

}

func udpAddrHash(a *net.UDPAddr) [6]byte {
	var b [6]byte
	copy(b[:4], []byte(a.IP)[:4])
	p := uint16(a.Port)
	b[4] = byte((p >> 8) & 0xFF)
	b[5] = byte(p & 0xFF)
	return b
}

type hUDPAddr struct {
	u    *net.UDPAddr
	hash [6]byte
}

func newhUDPAddr(a *net.UDPAddr) *hUDPAddr {
	return &hUDPAddr{a, udpAddrHash(a)}
}

// gohop Peer is a record of a peer's available UDP addrs
type VpnPeer struct {
	id           uint64
	ip           net.IP
	addrs        map[[6]byte]int
	_addrs_lst   []*hUDPAddr   // i know it's ugly!
	seq          uint32
	state        int32
	hsDone       chan struct{} // Handshake done
	recvBuffer   *vpnPacketBuffer
	srv          *VpnServer
	_lock        sync.RWMutex
	lastSeenTime time.Time
}

func newHopPeer(id uint64, srv *VpnServer, addr *net.UDPAddr, idx int) *VpnPeer {
	hp := new(VpnPeer)
	hp.id = id
	hp._addrs_lst = make([]*hUDPAddr, 0)
	hp.addrs = make(map[[6]byte]int)
	hp.state = HOP_STAT_INIT
	hp.seq = 0
	hp.srv = srv
	hp.recvBuffer = newHopPacketBuffer(srv.toIface)
	// logger.Debug("%v, %v", hp.recvBuffer, hp.srv)

	a := newhUDPAddr(addr)
	hp._addrs_lst = append(hp._addrs_lst, a)
	hp.addrs[a.hash] = idx

	return hp
}

func (h *VpnPeer) Seq() uint32 {
	return atomic.AddUint32(&h.seq, 1)
}

func (h *VpnPeer) addr() (*net.UDPAddr, int, bool) {
	defer h._lock.RUnlock()
	h._lock.RLock()
	addr := randAddr(h._addrs_lst)
	idx, ok := h.addrs[addr.hash]

	return addr.u, idx, ok
}

func (h *VpnPeer) insertAddr(addr *net.UDPAddr, idx int) {
	defer h._lock.Unlock()
	h._lock.Lock()
	a := newhUDPAddr(addr)
	if _, found := h.addrs[a.hash]; !found {
		h.addrs[a.hash] = idx
		h._addrs_lst = append(h._addrs_lst, a)
	}
}
