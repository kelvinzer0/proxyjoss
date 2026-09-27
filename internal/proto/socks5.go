// Package proto holds pure protocol codecs: bytes in, bytes out, no sockets and
// no I/O policy. Both the inbound SOCKS5 server and the upstream SOCKS5 client
// build on it, which means the wire format is tested once rather than twice.
package proto

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 constants from RFC 1928 (protocol) and RFC 1929 (username/password
// authentication).
const (
	Socks5Version = 0x05

	AuthNone     byte = 0x00
	AuthUserPass byte = 0x02
	AuthNoAccept byte = 0xff

	AuthUserPassVersion byte = 0x01

	CmdConnect byte = 0x01
	CmdBind    byte = 0x02
	CmdUDP     byte = 0x03

	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x03
	AddrIPv6   byte = 0x04

	ReplySuccess           byte = 0x00
	ReplyGeneralFailure    byte = 0x01
	ReplyNotAllowed        byte = 0x02
	ReplyNetworkUnreach    byte = 0x03
	ReplyHostUnreach       byte = 0x04
	ReplyConnectionRefused byte = 0x05
	ReplyTTLExpired        byte = 0x06
	ReplyCmdNotSupported   byte = 0x07
	ReplyAddrNotSupported  byte = 0x08
)

// Socks5Error is a SOCKS5 reply carrying a non-zero status.
type Socks5Error struct {
	// Code is the reply byte from the peer.
	Code byte
	// Op describes what we were doing, for example "CONNECT example.com:443".
	Op string
}

func (e *Socks5Error) Error() string {
	return fmt.Sprintf("socks5 %s: %s (reply 0x%02x)", e.Op, Socks5StatusText(e.Code), e.Code)
}

// Socks5StatusText maps a reply code to the wording RFC 1928 gives it.
func Socks5StatusText(code byte) string {
	switch code {
	case ReplySuccess:
		return "succeeded"
	case ReplyGeneralFailure:
		return "general failure"
	case ReplyNotAllowed:
		return "connection not allowed by ruleset"
	case ReplyNetworkUnreach:
		return "network unreachable"
	case ReplyHostUnreach:
		return "host unreachable"
	case ReplyConnectionRefused:
		return "connection refused"
	case ReplyTTLExpired:
		return "TTL expired"
	case ReplyCmdNotSupported:
		return "command not supported"
	case ReplyAddrNotSupported:
		return "address type not supported"
	default:
		return "unknown failure"
	}
}

// Socks5Request is a decoded CONNECT request.
type Socks5Request struct {
	Cmd  byte
	Host string
	Port int
}

// Socks5Greeting is the client's opening offer.
type Socks5Greeting struct {
	Methods []byte
}

// HasMethod reports whether the client offered an auth method.
func (g Socks5Greeting) HasMethod(m byte) bool {
	for _, v := range g.Methods {
		if v == m {
			return true
		}
	}
	return false
}

// Socks5UserPass is a username/password authentication attempt (RFC 1929).
type Socks5UserPass struct {
	Username string
	Password string
}

// ReadSocks5Greeting decodes the client's version byte and method list.
func ReadSocks5Greeting(r io.Reader) (Socks5Greeting, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return Socks5Greeting{}, fmt.Errorf("read socks5 greeting: %w", err)
	}
	if head[0] != Socks5Version {
		return Socks5Greeting{}, fmt.Errorf("socks5: unsupported version 0x%02x, want 0x05", head[0])
	}
	if head[1] == 0 {
		return Socks5Greeting{}, errors.New("socks5: client offered no auth methods")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return Socks5Greeting{}, fmt.Errorf("read socks5 auth methods: %w", err)
	}
	return Socks5Greeting{Methods: methods}, nil
}

// WriteSocks5MethodReply selects one auth method.
func WriteSocks5MethodReply(w io.Writer, method byte) error {
	_, err := w.Write([]byte{Socks5Version, method})
	return err
}

// ReadSocks5UserPass decodes an RFC 1929 authentication attempt.
func ReadSocks5UserPass(r io.Reader) (Socks5UserPass, error) {
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return Socks5UserPass{}, fmt.Errorf("read socks5 auth version: %w", err)
	}
	if ver[0] != AuthUserPassVersion {
		return Socks5UserPass{}, fmt.Errorf("socks5: unsupported auth version 0x%02x, want 0x01", ver[0])
	}
	user, err := readSocks5String(r)
	if err != nil {
		return Socks5UserPass{}, fmt.Errorf("read socks5 username: %w", err)
	}
	pass, err := readSocks5String(r)
	if err != nil {
		return Socks5UserPass{}, fmt.Errorf("read socks5 password: %w", err)
	}
	return Socks5UserPass{Username: user, Password: pass}, nil
}

// AppendSocks5UserPass encodes a username/password authentication message
// (RFC 1929): a version byte followed by two length-prefixed fields.
//
// The password length byte is mandatory even when the password is empty. A
// message that stops after the username blocks a strict server forever, so the
// empty case must still be written in full.
func AppendSocks5UserPass(dst []byte, username, password string) []byte {
	dst = append(dst, AuthUserPassVersion)
	dst = appendSocks5String(dst, username)
	dst = appendSocks5String(dst, password)
	return dst
}

// WriteSocks5UserPassResult reports whether authentication succeeded.
func WriteSocks5UserPassResult(w io.Writer, ok bool) error {
	status := byte(0x00)
	if !ok {
		status = 0x01
	}
	_, err := w.Write([]byte{AuthUserPassVersion, status})
	return err
}

func appendSocks5String(dst []byte, s string) []byte {
	// A field longer than 255 bytes cannot be expressed in the format. Truncating
	// would send a wrong password, so the field is simply cut and the server
	// will reject it, which is the honest outcome.
	if len(s) > 255 {
		s = s[:255]
	}
	dst = append(dst, byte(len(s)))
	return append(dst, s...)
}

func readSocks5String(r io.Reader) (string, error) {
	var l [1]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", err
	}
	if l[0] == 0 {
		return "", nil
	}
	b := make([]byte, int(l[0]))
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// AppendSocks5Request encodes a request. Numeric addresses are sent in their
// binary form and everything else as a domain name, so an upstream proxy
// resolves the name the same way the client would have.
func AppendSocks5Request(dst []byte, cmd byte, host string, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: port %d out of range", port)
	}
	dst = append(dst, Socks5Version, cmd, 0x00)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, AddrIPv4)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, AddrIPv6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		if host == "" {
			return nil, errors.New("socks5: empty destination host")
		}
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5: host %q exceeds 255 bytes", host)
		}
		dst = append(dst, AddrDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	return append(dst, byte(port>>8), byte(port)), nil
}

// ReadSocks5Request decodes a request header.
func ReadSocks5Request(r io.Reader) (Socks5Request, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return Socks5Request{}, fmt.Errorf("read socks5 request: %w", err)
	}
	if head[0] != Socks5Version {
		return Socks5Request{}, fmt.Errorf("socks5: unsupported version 0x%02x in request", head[0])
	}
	var host string
	switch head[3] {
	case AddrIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return Socks5Request{}, err
		}
		host = net.IP(b).String()
	case AddrIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return Socks5Request{}, err
		}
		host = net.IP(b).String()
	case AddrDomain:
		name, err := readSocks5String(r)
		if err != nil {
			return Socks5Request{}, fmt.Errorf("read socks5 domain: %w", err)
		}
		host = name
	default:
		return Socks5Request{}, fmt.Errorf("socks5: unsupported address type 0x%02x", head[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Socks5Request{}, err
	}
	return Socks5Request{
		Cmd:  head[1],
		Host: host,
		Port: int(p[0])<<8 | int(p[1]),
	}, nil
}

// ReadSocks5Reply decodes a reply and returns the bound host.
//
// Callers that tunnel payload must read the reply through a bufio.Reader and
// check Buffered afterwards, because a peer may pipeline the first payload bytes
// behind the reply and those bytes would otherwise be lost.
func ReadSocks5Reply(r io.Reader) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", fmt.Errorf("read socks5 reply: %w", err)
	}
	if head[0] != Socks5Version {
		return "", fmt.Errorf("socks5: unsupported version 0x%02x in reply", head[0])
	}
	if head[1] != ReplySuccess {
		return "", &Socks5Error{Code: head[1]}
	}
	return readSocks5Addr(r, head[3])
}

func readSocks5Addr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case AddrIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case AddrIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case AddrDomain:
		return readSocks5String(r)
	default:
		return "", fmt.Errorf("socks5: unsupported address type 0x%02x", atyp)
	}
}

// AppendSocks5Reply encodes a reply with a zero bound address, which every
// client accepts. Encoding the real local address would be more informative but
// is not required and would leak the rotator's internals.
func AppendSocks5Reply(dst []byte, code byte) []byte {
	return append(dst,
		Socks5Version, code, 0x00, AddrIPv4,
		0, 0, 0, 0, // bound IPv4
		0, 0, // bound port
	)
}

// WriteSocks5Reply writes a reply with a zero bound address.
func WriteSocks5Reply(w io.Writer, code byte) error {
	_, err := w.Write(AppendSocks5Reply(nil, code))
	return err
}

// HostPort renders a host and port for logging and for HTTP CONNECT targets.
func HostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
