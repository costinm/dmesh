//go:build !nolwip

package lwip

import (
	"context"
	"io"
	"log"
	"net"

	"github.com/costinm/go-tun2socks/core"
	//"github.com/costinm/ugate/pkg/udp"

	"github.com/songgao/water"
)

type LWIP struct {
	Dev string

	TCPOut func(nc net.Conn, target *net.TCPAddr, la *net.TCPAddr)
}

//func(nc net.Conn, target *net.TCPAddr, la *net.TCPAddr) {
//	log.Println("TUN TCP ", target, la)
//	dest := target.String()
//
//	rc, err := ll.Mesh.DialContext(context.Background(), "tcp", dest)
//	if err != nil {
//		nc.Close()
//		return
//	}
//	nio.Proxy(rc, nc, nc, dest)
//
//}

func (l *LWIP) Provision(ctx context.Context) error {
	dev := l.Dev
	if dev == "" {
		dev = "dmesh0"
		//return nil
	}

	fd, err := OpenTun(dev)
	if err != nil {
		return nil
	}

	log.Println("Using LWIP tun", dev)

	t := NewTUNFD(fd, l.TCPOut, func(dstAddr net.IP, dstPort uint16,
		localAddr net.IP, localPort uint16,
		data []byte) {
		log.Println("TProxy UDP ", dstAddr, dstPort, localAddr, localPort, len(data))
	})
	// Use the TUN for transparent UDP write ?
	//udp.TransparentUDPWriter = t
	return nil
}

// Setup:
//
//	ip tuntap add dev dmesh0 mode tun user build

const (
	MTU = 1500
)

// UdpWriter is the interface implemented by the TunTransport, to send
// packets back to the virtual interface
//type UdpWriter interface {
//	WriteTo(data []byte, dstAddr *net.UDPAddr, srcAddr *net.UDPAddr) (int, error)
//}

// Interface implemented by TUNHandler.
// Important: for android the system makes sure tun is the default route, but
// packets from the VPN app are excluded.
//
// On Linux we need a similar setup. This still requires iptables to mark
// packets from istio-proxy, and use 2 routing tables.

//type CloseWriter interface {
//	CloseWrite() error
//}

// If NET_CAP or owner, open the tun.
func OpenTun(ifn string) (io.ReadWriteCloser, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Persist: true,
		},
	}
	config.Name = ifn
	ifce, err := water.New(config)

	if err != nil {
		return nil, err
	}
	return ifce.ReadWriteCloser, nil
}

// LWIPTun adapts the LWIP interfaces - in particular UDPConn
//
// Implements UDPWriter (defined in many packages)
type LWIPTun struct {
	lwip       core.LWIPStack
	tcpHandler func(nc net.Conn, target *net.TCPAddr, la *net.TCPAddr)
	udpHandler func(dstAddr net.IP, dstPort uint16,
		localAddr net.IP, localPort uint16,
		data []byte)
}

func (t *LWIPTun) HandleUdp(dstAddr net.IP, dstPort uint16, localAddr net.IP, localPort uint16, data []byte) {
	t.udpHandler(dstAddr, dstPort, localAddr, localPort, data)
}

// Called by udp_conn.newUDPConn. conn will hold a chan of packets.
// If err != nil - conn will be closed
// Else ReceiveTo will be called on each pending packet.
func (t *LWIPTun) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	return nil
}

// Will get pending packets for 'connections'.
// The handling of udpRecvFn:
// - convert srcAddr/dstAddr params
// - srcAddr used to construct a 'connection'
// - if not found - construct one.
func (t *LWIPTun) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	la := conn.LocalAddr()
	go t.udpHandler(addr.IP, uint16(addr.Port), la.IP, uint16(la.Port), data)
	return nil
}

func (t *LWIPTun) Handle(conn net.Conn, target *net.TCPAddr) error {
	// Must return - TCP con will be moved to connected after return.
	// err will abort. While this is executing, will stay in connected
	// TODO: extra param to do all processing and do the proxy in background.
	go t.tcpHandler(conn, target, nil)
	return nil
}

// Inject a packet into the UDP stack.
// dst us a local address, corresponding to an open local UDP port.
// TODO: find con from connect, close the conn periodically
func (t *LWIPTun) WriteTo(data []byte, dst *net.UDPAddr, src *net.UDPAddr) (int, error) {
	core.WriteTo(data, dst, src)

	return 0, nil
}

func NewTUNFD(tunDev io.ReadWriteCloser, handler func(nc net.Conn, target *net.TCPAddr, la *net.TCPAddr), udpNat func(dstAddr net.IP, dstPort uint16,
	localAddr net.IP, localPort uint16,
	data []byte)) *LWIPTun {

	lwip := core.NewLWIPStack()

	t := &LWIPTun{
		lwip:       lwip,
		tcpHandler: handler,
		udpHandler: udpNat,
	}

	core.RegisterTCPConnHandler(t)
	//core.RegisterTCPConnHandler(redirect.NewTCPHandler("127.0.0.1:5201"))

	core.RegisterUDPConnHandler(t)
	core.RegisterRawUDPHandler(t)

	core.RegisterOutputFn(func(data []byte) (int, error) {
		//log.Println("ip2tunW: ", len(data))
		return tunDev.Write(data)
	})

	// Copy packets from tun device to lwip stack, it's the main loop.
	go func() {
		ba := make([]byte, 10*MTU)
		for {
			n, err := tunDev.Read(ba)
			if err != nil {
				log.Println("Err tun", err)
				return
			}
			//log.Println("tun2ipR: ", n)
			_, err = lwip.Write(ba[0:n])
			if err != nil {
				log.Println("Err lwip", err)
				return
			}
		}
	}()

	return t
}
