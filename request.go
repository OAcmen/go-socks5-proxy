package go_socks5_proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

var (
	unrecognizedAddrType = fmt.Errorf("unrecognized address type")
)

type Socks5AddrType struct {
	Type uint8
	FQDN string
	IP   net.IP
	Port int
}

func (addr *Socks5AddrType) String() string {
	if addr.FQDN != "" {
		return fmt.Sprintf("type:%d %s (%s):%d", addr.Type, addr.FQDN, addr.IP, addr.Port)
	}
	return fmt.Sprintf("type:%d %s:%d", addr.Type, addr.IP, addr.Port)
}

func (addr *Socks5AddrType) Address() string {
	if 0 != len(addr.IP) {
		return net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
	}
	return net.JoinHostPort(addr.FQDN, strconv.Itoa(addr.Port))
}

type Request struct {
	// Version is protocol version
	Version uint8
	// Command is requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// RemoteAddr represents the network address of the sender of the request.
	RemoteAddr *Socks5AddrType
	// DestAddr represents the desired destination of the sending requests.
	DestAddr *Socks5AddrType
	// realDestAddr represents the actual destination of the sending requests
	// (maybe affected by rewrite).
	realDestAddr *Socks5AddrType
	bufConn      io.Reader
}

// NewRequest creates a new Request from the tcp connection.
/**
+-----+-----+-----+-----------+----------+
| VER | CMD | RSV |  DST.ADDR | DST.PORT |
+-----+-----+-----+-----------+----------+
|  1  |  1  | X00 |    Var    |     2    |
+-----+-----+-----+-----------+----------+

*/
func NewRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil, fmt.Errorf("failed to get command version: %v", err)
	}

	if header[0] != socks5Version {
		return nil, fmt.Errorf("unspported command version: %v", header[0])
	}

	dest, err := readSocks5AddrType(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

// readSocks5AddrType is used to read Socks5AddrType.
// Expects an address type byte, followed by the address and port
/**
SOCKS5 address: (Socks5AddrType)
+----------+------+--------------+
|          | TYPE |     ADDR     |
+----------+------+--------------+
|byte count|  1   |   variable   |
+----------+------+--------------+
*/
func readSocks5AddrType(r io.Reader) (*Socks5AddrType, error) {
	d := &Socks5AddrType{}

	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}
	d.Type = addrType[0]

	switch d.Type {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, 4); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, 16); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = int(binary.BigEndian.Uint16(port))

	return d, nil
}

// sendReply is used to send a reply message.
/**
+----------+-----+--------+-----+----------+----------+
|          | VER | STATUS | RSV | BND.ADDR | BND.PORT |
+----------+-----+--------+-----+----------+----------+
|byte count|  1  |    1   | X00 | variable |     2    |
+----------+-----+--------+-----+----------+----------+
SOCKS5 address: (Socks5AddrType)
+----------+------+--------------+
|          | TYPE |     ADDR     |
+----------+------+--------------+
|byte count|  1   |   variable   |
+----------+------+--------------+
*/
func sendReply(w io.Writer, resp uint8, socks5Addr *Socks5AddrType) error {
	// Format the address
	var (
		addrType uint8
		addrBody []byte
		addrPort uint16
	)

	if socks5Addr != nil {
		addrType = socks5Addr.Type
		addrPort = uint16(socks5Addr.Port)
		switch socks5Addr.Type {
		case fqdnAddress:
			addrBody = append([]byte{byte(len(socks5Addr.FQDN))}, socks5Addr.FQDN...)
		case ipv4Address:
			addrBody = []byte(socks5Addr.IP.To4())
		case ipv6Address:
			addrBody = []byte(socks5Addr.IP.To16())
		default:
			return fmt.Errorf("failed to format address: %v", socks5Addr)
		}
	} else {
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0
	}

	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0
	msg[3] = addrType
	copy(msg[4:], addrBody)
	binary.BigEndian.PutUint16(msg[4+len(addrBody):], addrPort)

	_, err := w.Write(msg)
	return err
}
