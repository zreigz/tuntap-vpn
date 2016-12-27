package vpn

import (
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	. "github.com/zreigz/tuntap-vpn/utils"
	"github.com/songgao/water"
)

var net_gateway, net_nic string

type route struct {
	dest, nextHop, iface string
}

type VpnClient struct {
	// config
	cfg            ClientConfig
	// interface
	iface          *water.Interface
	// ip addr
	ip             net.IP

	// session id
	sid            [4]byte
	// session state
	state          int32

	// net to interface
	toIface        chan *VpnPacket
	// buffer for packets from net
	recvBuf        *vpnPacketBuffer
	// channel to send frames to net
	toNet          chan *VpnPacket

	handshakeDone  chan struct{}
	handshakeError chan struct{}
	finishAck      chan byte
	// state variable to ensure serverRoute added
	srvRoute       int32
	// routes need to be clean in the end
	routes         []string
	// sequence number
	seq            uint32
}

func NewClient(cfg ClientConfig) error {
	var err error

	if err != nil {
		return err
	}

	if cfg.MTU != 0 {
		MTU = cfg.MTU
	}

	vpnClient := new(VpnClient)
	rand.Read(vpnClient.sid[:])
	vpnClient.toIface = make(chan *VpnPacket, 128)
	vpnClient.toNet = make(chan *VpnPacket, 128)
	vpnClient.recvBuf = newHopPacketBuffer(vpnClient.toIface)
	vpnClient.cfg = cfg
	vpnClient.state = HOP_STAT_INIT
	vpnClient.handshakeDone = make(chan struct{})
	vpnClient.handshakeError = make(chan struct{})
	vpnClient.finishAck = make(chan byte)
	vpnClient.srvRoute = 0
	vpnClient.routes = make([]string, 0, 1024)

	go vpnClient.cleanUp()

	iface, err := newTun("")
	if err != nil {
		return err
	}
	vpnClient.iface = iface

	net_gateway, net_nic, err = getNetGateway()
	logger.Debug("Net Gateway: %s %s", net_gateway, net_nic)
	if err != nil {
		return err
	}

	for port := cfg.PortStart; port <= cfg.PortEnd; port++ {
		server := fmt.Sprintf("%s:%d", cfg.Server, port)
		go vpnClient.handleUDP(server)
	}

	// wait until handshake done
	wait_handshake:
	for {
		select {
		case <-vpnClient.handshakeDone:
			logger.Info("Handshake Success")
			break wait_handshake
		case <-vpnClient.handshakeError:
			return errors.New("Handshake Fail")
		case <-time.After(3 * time.Second):
			logger.Info("Handshake Timeout")
			atomic.CompareAndSwapInt32(&vpnClient.state, HOP_STAT_HANDSHAKE, HOP_STAT_INIT)
		}
	}

	err = redirectGateway(iface.Name(), tun_peer.String())
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	vpnClient.handleInterface()

	return errors.New("Not expected to exit")
}

func (clt *VpnClient) handleInterface() {
	// network packet to interface
	go func() {
		for {
			hp := <-clt.toIface
			// logger.Debug("New Net packet to device")
			_, err := clt.iface.Write(hp.payload)
			// logger.Debug("n: %d, len: %d", n, len(hp.payload))
			if err != nil {
				logger.Error(err.Error())
				return
			}
		}
	}()

	frame := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := clt.iface.Read(frame)
		if err != nil {
			logger.Error(err.Error())
			return
		}

		buf := make([]byte, n + HOP_HDR_LEN)
		copy(buf[HOP_HDR_LEN:], frame[:n])
		hp := new(VpnPacket)
		hp.payload = buf[HOP_HDR_LEN:]
		hp.buf = buf
		hp.Seq = clt.Seq()
		clt.toNet <- hp
		/*
		   if hopFrager == nil {
		       // if no traffic morphing
		       // Hack to reduce memcopy

		   } else {
		       // with traffic morphing
		       packets := hopFrager.Fragmentate(clt, buf[HOP_HDR_LEN:])
		       for _, hp := range(packets) {
		           clt.toNet <- hp
		       }
		   }
		*/
	}
}

func (clt *VpnClient) handleUDP(server string) {
	udpAddr, _ := net.ResolveUDPAddr("udp", server)
	udpConn, _ := net.DialUDP("udp", nil, udpAddr)

	logger.Debug(udpConn.RemoteAddr().String())

	// packet map
	pktHandle := map[byte](func(*net.UDPConn, *VpnPacket)){
		HOP_FLG_HSH | HOP_FLG_ACK: clt.handleHandshakeAck,
		HOP_FLG_HSH | HOP_FLG_FIN: clt.handleHandshakeError,
		HOP_FLG_PSH:               clt.handleHeartbeat,
		HOP_FLG_PSH | HOP_FLG_ACK: clt.handleKnockAck,
		HOP_FLG_DAT:               clt.handleDataPacket,
		HOP_FLG_DAT | HOP_FLG_MFR: clt.handleDataPacket,
		HOP_FLG_FIN | HOP_FLG_ACK: clt.handleFinishAck,
		HOP_FLG_FIN:               clt.handleFinish,
	}

	go func() {
		for {
			clt.knock(udpConn)
			n := mrand.Intn(1000)
			time.Sleep(time.Duration(n) * time.Millisecond)
			clt.handeshake(udpConn)
			select {
			case <-clt.handshakeDone:
				return
			case <-time.After(5 * time.Second):
				logger.Debug("Handshake timeout, retry")
			}
		}
	}()

	go func() {
		var intval time.Duration

		intval = time.Second * 30

		for {
			time.Sleep(intval)
			if clt.state == HOP_STAT_WORKING {
				clt.knock(udpConn)
			}
		}
	}()

	if atomic.CompareAndSwapInt32(&clt.srvRoute, 0, 1) {
		if udpAddr, ok := udpConn.RemoteAddr().(*net.UDPAddr); ok {
			srvIP := udpAddr.IP.To4()
			if srvIP != nil {
				srvDest := srvIP.String() + "/32"
				addRoute(srvDest, net_gateway, net_nic)
				clt.routes = append(clt.routes, srvDest)
			}
		}
	}


	// forward iface frames to network
	go func() {
		for {
			hp := <-clt.toNet
			hp.setSid(clt.sid)
			// logger.Debug("New iface frame")
			// dest := waterutil.IPv4Destination(frame)
			// logger.Debug("ip dest: %v", dest)

			udpConn.Write(hp.Pack())
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		//logger.Debug("waiting for udp packet")
		n, err := udpConn.Read(buf)
		//logger.Debug("New UDP Packet, len: %d", n)
		if err != nil {
			logger.Error(err.Error())
			continue
		}

		hp := unpackHopPacket(buf[:n])
		if err != nil {
			logger.Debug("Error depacketing")
			continue
		}
		if handle_func, ok := pktHandle[hp.Flag]; ok {
			handle_func(udpConn, hp)
		} else {
			logger.Error("Unkown flag: %x", hp.Flag)
		}
	}
}

func (clt *VpnClient) Seq() uint32 {
	return atomic.AddUint32(&clt.seq, 1)
}

func (clt *VpnClient) toServer(u *net.UDPConn, flag byte, payload []byte, noise bool) {
	hp := new(VpnPacket)
	hp.Flag = flag
	hp.Seq = clt.Seq()
	hp.setPayload(payload)
	if noise {
		hp.addNoise(mrand.Intn(MTU - 64 - len(payload)))
	}
	u.Write(hp.Pack())
}

// knock server port or heartbeat
func (clt *VpnClient) knock(u *net.UDPConn) {
	clt.toServer(u, HOP_FLG_PSH, clt.sid[:], true)
}

// handshake with server
func (clt *VpnClient) handeshake(u *net.UDPConn) {
	res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)
	// logger.Debug("raced for handshake: %v", res)

	if res {
		logger.Info("start handeshaking")
		clt.toServer(u, HOP_FLG_HSH, clt.sid[:], true)
	}
}

// finish session
func (clt *VpnClient) finishSession() {
	logger.Info("Finishing Session")
	atomic.StoreInt32(&clt.state, HOP_STAT_FIN)
	hp := new(VpnPacket)
	hp.Flag = HOP_FLG_FIN
	hp.setPayload(clt.sid[:])
	hp.Seq = clt.Seq()
	clt.toNet <- hp
	clt.toNet <- hp
	clt.toNet <- hp
}

// heartbeat ack
func (clt *VpnClient) handleKnockAck(u *net.UDPConn, hp *VpnPacket) {
	return
}

// heartbeat ack
func (clt *VpnClient) handleHeartbeat(u *net.UDPConn, hp *VpnPacket) {
	logger.Debug("Heartbeat from server")
	clt.toServer(u, HOP_FLG_PSH | HOP_FLG_ACK, clt.sid[:], true)
}

// handle handeshake ack
func (clt *VpnClient) handleHandshakeAck(u *net.UDPConn, hp *VpnPacket) {
	if atomic.LoadInt32(&clt.state) == HOP_STAT_HANDSHAKE {
		proto_version := hp.payload[0]
		if proto_version != HOP_PROTO_VERSION {
			logger.Error("Incompatible protocol version!")
			os.Exit(1)
		}

		by := hp.payload[1:6]
		ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", by[0], by[1], by[2], by[3], by[4])

		ip, subnet, _ := net.ParseCIDR(ipStr)

		setTunIP(clt.iface, ip, subnet)

		fixMSS(clt.iface.Name(), false)

		res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
		if !res {
			logger.Error("Client state not expected: %d", clt.state)
		}
		logger.Info("Session Initialized")
		close(clt.handshakeDone)
	}

	logger.Debug("Handshake Ack to Server")
	clt.toServer(u, HOP_FLG_HSH | HOP_FLG_ACK, clt.sid[:], true)
}

// handle handshake fail
func (clt *VpnClient) handleHandshakeError(u *net.UDPConn, hp *VpnPacket) {
	close(clt.handshakeError)
}

// handle data packet
func (clt *VpnClient) handleDataPacket(u *net.UDPConn, hp *VpnPacket) {
	// logger.Debug("New HopPacket Seq: %d", packet.Seq)
	clt.recvBuf.Push(hp)
}

// handle finish ack
func (clt *VpnClient) handleFinishAck(u *net.UDPConn, hp *VpnPacket) {
	clt.finishAck <- byte(1)
}

// handle finish
func (clt *VpnClient) handleFinish(u *net.UDPConn, hp *VpnPacket) {
	logger.Info("Finish")
	pid := os.Getpid()
	syscall.Kill(pid, syscall.SIGTERM)
}

func (clt *VpnClient) cleanUp() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	logger.Info("Cleaning Up")

	delRoute("0.0.0.0/1")
	delRoute("128.0.0.0/1")

	clearMSS(clt.iface.Name(), false)

	timeout := time.After(3 * time.Second)
	if clt.state != HOP_STAT_INIT {
		clt.finishSession()
	}

	select {
	case <-clt.finishAck:
		logger.Info("Finish Acknowledged")
	case <-timeout:
		logger.Info("Timeout, give up")
	}

	for _, dest := range clt.routes {
		delRoute(dest)
	}

	os.Exit(0)
}

