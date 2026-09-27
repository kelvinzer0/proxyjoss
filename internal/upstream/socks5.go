package upstream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/proto"
)

// Socks5ReplyError is a SOCKS5 reply with a non-zero status, carrying the
// meaning RFC 1928 assigns to it.
type Socks5ReplyError struct {
	// Code is the reply byte.
	Code byte
	// Op describes the request that was rejected.
	Op string
}

func (e *Socks5ReplyError) Error() string {
	return fmt.Sprintf("socks5 %s: %s (0x%02x)", e.Op, proto.Socks5StatusText(e.Code), e.Code)
}

// Socks5Connect negotiates a SOCKS5 CONNECT over an already-open connection.
//
// It is used to reach a destination through a genuine forward proxy, and also
// serves as the SOCKS5 server implementation for the inbound listener, so the
// handshake is exercised by tests in both directions.
//
// The deadline covers only the negotiation; it is cleared on return so a slow
// tunnel is not cut short by the handshake timeout.
func Socks5Connect(ctx context.Context, conn net.Conn, target Target, username, password string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	deadline, _ := ctx.Deadline()
	if err := proto.SetDeadline(conn, deadline, timeout); err != nil {
		return nil, err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	// The reader is created here rather than inside the negotiation so the
	// leftover buffer can be handed to the caller instead of being discarded.
	br := bufio.NewReader(conn)
	if err := socks5Negotiate(ctx, br, conn, target, username, password); err != nil {
		return nil, err
	}
	// The reply read is buffered, so payload bytes that arrived in the same
	// segment as the reply are already inside the reader. Returning the raw
	// connection would silently drop them, which corrupts the tunnel for any
	// client that pipelines its first bytes right after the handshake.
	return proto.NewBufferedConn(conn, br), nil
}

// socks5Negotiate runs the greeting, optional authentication and the CONNECT
// request. Reads go through br and writes go to conn; any payload already in br
// belongs to the tunnel and must be preserved.
func socks5Negotiate(_ context.Context, br *bufio.Reader, conn net.Conn, target Target, username, password string) error {
	// Offer both "no auth" and username/password. Some upstreams insist on the
	// latter even when the credentials are empty.
	if _, err := conn.Write([]byte{
		proto.Socks5Version, 2, proto.AuthNone, proto.AuthUserPass,
	}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}

	method, err := readMethod(br)
	if err != nil {
		return err
	}
	switch method {
	case proto.AuthNone:
		// Nothing to do.
	case proto.AuthUserPass:
		if _, err := conn.Write(proto.AppendSocks5UserPass(nil, username, password)); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		var result [2]byte
		if _, err := io.ReadFull(br, result[:]); err != nil {
			return fmt.Errorf("socks5 auth result: %w", err)
		}
		if result[1] != 0x00 {
			return errors.New("socks5: upstream rejected the offered credentials")
		}
	case proto.AuthNoAccept:
		return errors.New("socks5: upstream rejected every offered auth method")
	default:
		return fmt.Errorf("socks5: upstream chose unsupported auth method 0x%02x", method)
	}

	request, err := proto.AppendSocks5Request(nil, proto.CmdConnect, target.Host, target.Port)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("socks5 request: %w", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(br, reply[:]); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}
	if reply[0] != proto.Socks5Version {
		return fmt.Errorf("socks5: unexpected reply version 0x%02x", reply[0])
	}
	if reply[1] != proto.ReplySuccess {
		return &Socks5ReplyError{Code: reply[1], Op: "CONNECT " + target.String()}
	}
	// Consume the bound address so the stream starts at the payload.
	return drainBoundAddr(br, reply[3])
}

// readMethod reads the selected auth method byte.
func readMethod(br *bufio.Reader) (byte, error) {
	sel := make([]byte, 2)
	if _, err := io.ReadFull(br, sel); err != nil {
		return 0, fmt.Errorf("socks5 method selection: %w", err)
	}
	if sel[0] != proto.Socks5Version {
		return 0, fmt.Errorf("socks5: unexpected version 0x%02x in method selection", sel[0])
	}
	return sel[1], nil
}

// drainBoundAddr consumes the address a SOCKS5 reply carries.
func drainBoundAddr(br *bufio.Reader, atyp byte) error {
	length := 0
	switch atyp {
	case proto.AddrIPv4:
		length = 4 + 2
	case proto.AddrIPv6:
		length = 16 + 2
	case proto.AddrDomain:
		var l [1]byte
		if _, err := br.Read(l[:]); err != nil {
			return fmt.Errorf("socks5 bound name length: %w", err)
		}
		length = int(l[0]) + 2
	default:
		return fmt.Errorf("socks5: unsupported bound address type 0x%02x", atyp)
	}
	if _, err := br.Discard(length); err != nil {
		return fmt.Errorf("socks5 bound address: %w", err)
	}
	return nil
}
