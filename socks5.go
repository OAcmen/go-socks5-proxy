package go_socks5_proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

/**
1. Client greeting. nego request:
client---->ss-local start a connection
negotiate with sock5 protocol
+----------+-----+---------------+-----------------+
|          | VER |     NAUTH     |     METHODS     |
+----------+-----+---------------+-----------------+
|byte count|  1  |       1       |    1 to 255     |
+----------+-----+---------------+-----------------+
VER
	SOCKS version(x05)
NAUTH
	Number of authentication methods supported, uint8(0x1)
AUTH
	Authentication methods, 1byte per method supported
	The authentication methods supported are numbered as follows:
 	* 0x00: no authentication required
	* 0x01: gssapi
	* 0x02: username/password
	* 0x03: to x7f IANA assigned
	* 0x04: to xfe reserved for private methods
	* 0xff: no acceptable methods
eg:b'\x05\x02\x00\02'  b'\x05\x01\x00'


2. Server authentication choice. reply:
the ss-local as server receives the greeting request, selects one of the methods,
then send the message as response to client.
+----------+-----+---------------+
|          | VER |     CAUTH     |
+----------+-----+---------------+
|byte count|  1  |      1        |
+----------+-----+---------------+
VER
	SOCKS version(0x05)
CAUTH
	Chosen authentication method, or 0xFF if no acceptable methods were offered.
eg: eg:b'\x05\x02'


3. Client authentication request, 0x02 username/password:
The subsequent authentication is method-dependent. Username and password authentication
(method 0x02)is described in RFC 1929(https://datatracker.ietf.org/doc/html/rfc1929)
+----------+-------+--------+---------+--------+---------+
|          |  VER  | ID_LEN |   ID    | PW_LEN |   PW    |
+----------+-------+--------+---------+--------+---------+
|byte count|   1   |    1   | dynamic |    1   | dynamic |
+----------+-------+--------+---------+--------+---------+
VER
	0x01 for current version of username/password authentication
ID_LEN, ID
	Username length, uint8; username as bytestring
PW_LEN, PW
	Password length, uint8; password as bytestring


4. Server subsequent authentication reply, 0x02 username/password:
server reply:
+----------+-----+---------------+
|          | VER |    STATUS     |
+----------+-----+---------------+
|byte count|  1  |      1        |
+----------+-----+---------------+
VER
	0x01 for current version of username/password authentication
STATUS
	0x00 success, otherwise failure, connection must be closed


5.  After authentication the connection can proceed. We first define an address datatype as:
SOCKS5 address: (Socks5AddrType)
+----------+------+--------------+
|          | TYPE |     ADDR     |
+----------+------+--------------+
|byte count|  1   |   variable   |
+----------+------+--------------+
TYPE
	type of the address. One of:
	* 0x01: IPv4 address
	* 0x03: Domain name
	* 0x04: IPv6 address
ADDR
	the address data that follows. Depending on type:
	* 4 bytes for IPv4 address
	* 1 byte of name length followed by 1-255 bytes for the domain name
	* 16 bytes for IPv6 address

Client connection request:
+----------+-----+-----+-----+----------+----------+
|          | VER | CMD | RSV | DST.ADDR | DST.PORT |
+----------+-----+-----+-----+----------+----------+
|byte count|  1  |  1  | X00 | variable |     2    |
+----------+-----+-----+-----+----------+----------+
VER
	SOCKS5 version(0x05)
CMD
	command here:
	* 0x01: CONNECT. establish a TCP/IP stream connection
	* 0x02: BIND. establish a TCP/IP port binding
	* 0x03: UDP ASSOCIATE. associate a UDP port
RSV
	reserved, must be 0x00
DST.ADDR
	destination address, see the Socks5AddrType above.
DST PORT
	the port number in a network byte order


6. Response packet from server:
+----------+-----+--------+-----+----------+----------+
|          | VER | STATUS | RSV | BND.ADDR | BND.PORT |
+----------+-----+--------+-----+----------+----------+
|byte count|  1  |    1   | X00 | variable |     2    |
+----------+-----+--------+-----+----------+----------+
VER
	SOCKS version(0x5)
STATUS
	the status code:
	* 0x00: request granted
	* 0x01: generate failure
	* 0x02: connection not allowed by ruleset
	* 0x03: network unreachable
	* 0x04: host unreachable
	* 0x05: connection refused by destination host
	* 0x06: TTL expired
	* 0x07: command not supported / protocol error
    * 0x08: address type not supported
RSV
	reserved, must be 0x00
BND.ADDR
	server bound address (RFC 1928) in the "SOCKS5 address" format specified above
BND.PORT
	server bound port number in a network byte order.
	it contains the port that socks server assigned to connect to the  target host
*/

const (
	socks5Version = uint8(5)
)

const (
	// ConnectCommand CMD
	ConnectCommand = uint8(1)
	// BindCommand CMD
	BindCommand = uint8(2)
	// AssociateCommand CMD
	AssociateCommand = uint8(3)

	// Socks5AddrType
	ipv4Address = uint8(1)
	fqdnAddress = uint8(3)
	ipv6Address = uint8(4)
)

// response packet status
const (
	successGranted uint8 = iota
	generateFailure
	ruleSetFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	socks5AddrTypeNotSupported
)

type Config struct {
	// AuthMethods can be provided to implement custom authentication.
	// By default, "no authentication" mode is enabled.
	// For username/password auth use UserPassAuthAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthAuthenticator to AuthMethods. If not provided,
	// and AuthMethods is nil, then "no authentication" mode is enabled.
	Credentials Credential

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting various commands.
	// If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate.
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// Dial optional function for dialing out.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Socks5Server is responsible for accepting connections and
// handling the details of the SOCKS5 protocol
type Socks5Server struct {
	config *Config

	// authMethods is provided from configuration.
	authMethods map[uint8]Authenticator
}

// NewServer creates a new Socks5Server.
func NewServer(conf *Config) (*Socks5Server, error) {
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthAuthenticator{Credentials: conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Socks5Server{
		config:      conf,
		authMethods: make(map[uint8]Authenticator),
	}

	for _, authMethod := range conf.AuthMethods {
		server.authMethods[authMethod.GetCode()] = authMethod
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it.
func (s *Socks5Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener.
func (s *Socks5Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			_ = s.ServeConn(conn)
		}()
	}
}

// ServeConn is used to serve a single connection.
func (s *Socks5Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[Error] socks: Failed to get version byte: %v", err)
		return err
	}

	// Verify the version
	if version[0] != socks5Version {
		err := fmt.Errorf("unsupported SOCKS version: %v", version[0])
		s.config.Logger.Printf("[ERROR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err := fmt.Errorf("failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERROR] socks: %v", err)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, socks5AddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &Socks5AddrType{
			Type: getIpAddressType(client),
			IP:   client.IP,
			Port: client.Port,
		}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("failed to handle request: %v", err)
		s.config.Logger.Printf("[ERROR] socks: %v", err)
		return err
	}

	return nil
}

// authenticate is used to handle connection authentication.
func (s *Socks5Server) authenticate(conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	header := []byte{0}
	if _, err := bufConn.Read(header); err != nil {
		return nil, err
	}
	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(bufConn, methods, numMethods); err != nil {
		return nil, err
	}
	for _, method := range methods {
		authenticator, found := s.authMethods[method]
		if found {
			return authenticator.Authenticate(bufConn, conn)
		}
	}

	_, err := conn.Write([]byte{socks5Version, NoAcceptable})
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("unsupported authentication mechanism")
}

// handleRequest is used for request processing after authentication
func (s *Socks5Server) handleRequest(req *Request, conn net.Conn) error {
	ctx := context.Background()

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		_ctx, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
			return fmt.Errorf("failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = _ctx
		dest.IP = addr
	}

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Socks5Server) handleConnect(ctx context.Context, conn net.Conn, req *Request) error {
	if ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleSetFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v blocked by ruleSet", req.DestAddr)
	}

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	local := target.LocalAddr().(*net.TCPAddr)
	bind := Socks5AddrType{
		Type: getIpAddressType(local),
		IP:   local.IP,
		Port: local.Port,
	}
	if err := sendReply(conn, successGranted, &bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.bufConn, errCh)
	go proxy(conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			return e
		}
	}

	return nil
}

func (s *Socks5Server) handleBind(ctx context.Context, conn net.Conn, req *Request) error {
	if ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleSetFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v blocked by ruleSet", req.DestAddr)
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

func (s *Socks5Server) handleAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	if ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleSetFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v blocked by ruleSet", req.DestAddr)
	}

	// TODO: Support associate
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}

func getIpAddressType(addr *net.TCPAddr) uint8 {
	if addr.IP.To4() != nil {
		return ipv4Address
	} else if addr.IP.To16() != nil {
		return ipv6Address
	}

	return ipv4Address
}
