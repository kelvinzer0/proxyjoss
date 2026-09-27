package inbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kelvinzer0/proxyjoss/internal/logging"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
	"github.com/kelvinzer0/proxyjoss/internal/upstream"
)

// socks5HandshakeTimeout bounds the greeting, authentication and request phase.
// The tunnel itself is not bounded.
const socks5HandshakeTimeout = 30 * time.Second

// Socks5Proxy serves the SOCKS5 protocol.
//
// Username and password authentication is always offered, because the username
// is the pool selector: there is no other way for a client to express which
// pool it wants. When no password is configured, a client that offers no
// credentials is given the default selector.
type Socks5Proxy struct {
	handler *Handler
	log     logging.Logger
	// defaultSelector is used for a client that sends no credentials.
	defaultSelector string
	// passwordRequired forces the username/password method.
	passwordRequired bool
}

// NewSocks5Proxy builds the SOCKS5 protocol handler.
func NewSocks5Proxy(h *Handler, log logging.Logger, cfg AuthConfig) *Socks5Proxy {
	if log == nil {
		log = logging.Discard{}
	}
	defaultSelector := cfg.DefaultSelector
	if defaultSelector == "" {
		defaultSelector = "global"
	}
	return &Socks5Proxy{
		handler:          h,
		log:              log,
		defaultSelector:  defaultSelector,
		passwordRequired: cfg.Required || cfg.Password != "",
	}
}

// Serve handles one client connection.
func (s *Socks5Proxy) Serve(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(socks5HandshakeTimeout))

	// negotiate already answers the greeting, and the only reply that follows
	// is the one for the request, so no reply is written here.
	cred, err := s.negotiate(client)
	if err != nil {
		s.log.Debugf("socks5 %s: %v", RemoteAddr(client), err)
		var socksErr *socks5HandshakeError
		if errors.As(err, &socksErr) && socksErr.replyCode != 0 {
			// A rejected method is answered with the two-byte selection byte;
			// every other failure gets a full request reply.
			if socksErr.replyCode == proto.AuthNoAccept {
				_ = proto.WriteSocks5MethodReply(client, proto.AuthNoAccept)
			} else {
				_ = proto.WriteSocks5Reply(client, socksErr.replyCode)
			}
		}
		return
	}
	// From here on the connection is a tunnel, so drop the handshake deadline.
	_ = client.SetDeadline(time.Time{})

	request, err := proto.ReadSocks5Request(client)
	if err != nil {
		s.log.Debugf("socks5 %s: %v", RemoteAddr(client), err)
		_ = proto.WriteSocks5Reply(client, proto.ReplyGeneralFailure)
		return
	}
	if request.Cmd != proto.CmdConnect {
		reject := RejectBadRequest("only CONNECT is supported, got command 0x%02x", request.Cmd)
		_ = proto.WriteSocks5Reply(client, reject.Socks)
		s.logRejection(request, reject)
		return
	}

	target := upstream.Target{Host: request.Host, Port: request.Port}
	result, err := s.handler.Open(ctx, cred, target)
	if err != nil {
		_ = proto.WriteSocks5Reply(client, socksCode(err))
		s.logRejection(request, err)
		return
	}
	defer result.Conn.Close()

	if err := proto.WriteSocks5Reply(client, proto.ReplySuccess); err != nil {
		return
	}
	s.handler.Tunnel(client, result.Conn)
}

// socks5HandshakeError is a failure during negotiation. replyCode, when set, is
// the SOCKS5 reply to send before closing.
type socks5HandshakeError struct {
	replyCode byte
	err       error
}

func (e *socks5HandshakeError) Error() string { return e.err.Error() }
func (e *socks5HandshakeError) Unwrap() error { return e.err }

func handshakeFailure(replyCode byte, format string, args ...any) error {
	return &socks5HandshakeError{replyCode: replyCode, err: fmt.Errorf(format, args...)}
}

// negotiate runs the greeting and authentication exchange and returns the
// credentials the client supplied.
func (s *Socks5Proxy) negotiate(c net.Conn) (Credentials, error) {
	greeting, err := proto.ReadSocks5Greeting(c)
	if err != nil {
		return Credentials{}, handshakeFailure(0, "%s", err.Error())
	}

	wantsUserPass := greeting.HasMethod(proto.AuthUserPass)
	wantsNone := greeting.HasMethod(proto.AuthNone)

	// A configured password makes credentials mandatory. Otherwise honour
	// whichever method the client prefers, which keeps curl and browsers happy.
	switch {
	case s.passwordRequired && !wantsUserPass:
		return Credentials{}, handshakeFailure(proto.AuthNoAccept,
			"client does not offer username/password authentication, which this proxy requires")
	case wantsUserPass:
		if err := proto.WriteSocks5MethodReply(c, proto.AuthUserPass); err != nil {
			return Credentials{}, handshakeFailure(0, "socks5 method reply: %s", err.Error())
		}
		return s.readUserPass(c)
	case wantsNone && !s.passwordRequired:
		if err := proto.WriteSocks5MethodReply(c, proto.AuthNone); err != nil {
			return Credentials{}, handshakeFailure(0, "socks5 method reply: %s", err.Error())
		}
		// Without credentials the client cannot express a selector, so the
		// configured default applies.
		return Credentials{Username: s.defaultSelector}, nil
	default:
		return Credentials{}, handshakeFailure(proto.AuthNoAccept, "no acceptable authentication method offered")
	}
}

func (s *Socks5Proxy) readUserPass(c net.Conn) (Credentials, error) {
	creds, err := proto.ReadSocks5UserPass(c)
	if err != nil {
		return Credentials{}, handshakeFailure(0, "%s", err.Error())
	}
	// The password is checked here, because RFC 1929 reserves this reply for the
	// authentication result: answering "success" to a wrong password and
	// refusing later at request time would tell the client it had authenticated
	// when it had not.
	//
	// The selector is deliberately not checked yet, so an unusable username
	// still produces an error that names the username the client sent.
	credentials := Credentials{Username: creds.Username, Password: creds.Password}
	if err := s.handler.auth.CheckPassword(credentials); err != nil {
		if writeErr := proto.WriteSocks5UserPassResult(c, false); writeErr != nil {
			return Credentials{}, handshakeFailure(0, "socks5 auth result: %s", writeErr.Error())
		}
		return Credentials{}, handshakeFailure(0, "socks5: the supplied password was not accepted")
	}
	if err := proto.WriteSocks5UserPassResult(c, true); err != nil {
		return Credentials{}, handshakeFailure(0, "socks5 auth result: %s", err.Error())
	}
	return credentials, nil
}

func (s *Socks5Proxy) logRejection(request proto.Socks5Request, err error) {
	var reject *RejectError
	if !errors.As(err, &reject) {
		s.log.Warnf("socks5: %s: %v", request.Host, err)
		return
	}
	if reject.Status < 500 {
		s.log.Debugf("socks5: rejected %s: %s", request.Host, reject.Reason)
		return
	}
	s.log.Warnf("socks5: %s: %s", request.Host, reject.Reason)
}

func socksCode(err error) byte {
	var reject *RejectError
	if errors.As(err, &reject) {
		return reject.Socks
	}
	return proto.ReplyGeneralFailure
}

// ParseProxyAuthorization decodes an HTTP Basic Proxy-Authorization header.
// Padding-free base64 is accepted because some clients omit it.
func ParseProxyAuthorization(header string) (Credentials, bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return Credentials{}, false
	}
	encoded := strings.TrimSpace(header[len(prefix):])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return Credentials{}, false
		}
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return Credentials{}, false
	}
	return Credentials{Username: user, Password: pass}, true
}
