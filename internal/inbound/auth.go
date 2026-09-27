// Package inbound serves clients. One listener answers both the HTTP proxy and
// the SOCKS5 protocol, and in both cases the proxy username selects which part
// of the upstream pool to rotate over.
package inbound

import (
	"crypto/subtle"
	"fmt"

	"github.com/kelvinzer0/proxyjoss/internal/domain"
	"github.com/kelvinzer0/proxyjoss/internal/proto"
)

// RejectError is a client-visible failure carrying the protocol-level code to
// report. One error type serves both protocols: the HTTP listener turns Status
// into a status line, the SOCKS5 listener turns it into a reply byte, and both
// therefore report the same underlying reason.
type RejectError struct {
	// Status is the HTTP status an HTTP client would see.
	Status int
	// Socks is the SOCKS5 reply byte a SOCKS5 client would see.
	Socks byte
	// Reason is a short client-safe explanation.
	Reason string
	// cause is the internal error, kept for logs but never sent to a client.
	cause error
}

func (e *RejectError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.Reason, e.cause)
	}
	return e.Reason
}

func (e *RejectError) Unwrap() error { return e.cause }

// Reject reasons. Keeping them in one place is what guarantees the HTTP and
// SOCKS5 paths cannot drift apart.
const (
	statusBadRequest = 400
	statusNotFound   = 404
	statusAuthFailed = 407
	statusBadGateway = 502
)

// ErrCredentials marks a rejected password.
var ErrCredentials = fmt.Errorf("invalid proxy credentials")

// ErrSelector marks a username that is not a valid selector.
var ErrSelector = fmt.Errorf("invalid selector")

// ErrUpstream marks a request that no pool entry could serve.
var ErrUpstream = fmt.Errorf("no usable upstream")

// RejectCredentials reports a failed password check.
func RejectCredentials() *RejectError {
	return &RejectError{
		Status: statusAuthFailed,
		Socks:  proto.ReplyGeneralFailure,
		Reason: "invalid proxy credentials",
		cause:  ErrCredentials,
	}
}

// RejectSelector reports a username outside the selector grammar.
func RejectSelector(cause error) *RejectError {
	return &RejectError{
		Status: statusBadRequest,
		Socks:  proto.ReplyNotAllowed,
		Reason: cause.Error(),
		cause:  ErrSelector,
	}
}

// RejectNoMatch reports a well-formed selector that matches no entry.
func RejectNoMatch(cause error) *RejectError {
	return &RejectError{
		Status: statusNotFound,
		Socks:  proto.ReplyNotAllowed,
		Reason: cause.Error(),
		cause:  ErrUpstream,
	}
}

// RejectUpstream reports that every candidate entry failed.
func RejectUpstream(cause error) *RejectError {
	return &RejectError{
		Status: statusBadGateway,
		Socks:  proto.ReplyHostUnreach,
		Reason: "no upstream proxy could reach the destination",
		cause:  cause,
	}
}

// RejectBadRequest reports a malformed client request.
func RejectBadRequest(format string, args ...any) *RejectError {
	return &RejectError{
		Status: statusBadRequest,
		Socks:  proto.ReplyCmdNotSupported,
		Reason: fmt.Sprintf(format, args...),
	}
}

// Credentials are the username and password a client presented.
type Credentials struct {
	Username string
	Password string
}

// Empty reports whether the client sent no username, in which case the
// configured default selector applies.
func (c Credentials) Empty() bool { return c.Username == "" }

// AuthConfig controls how credentials are judged.
type AuthConfig struct {
	// Required turns on password checking.
	Required bool
	// Password is the shared secret. A blank password accepts any value.
	Password string
	// AllowAnonymous permits a missing username, which then resolves to
	// DefaultSelector.
	AllowAnonymous bool
	// DefaultSelector is used when the client sends no username.
	DefaultSelector string
}

// passwordSet reports whether a password must be checked.
func (a AuthConfig) passwordSet() bool { return a.Required || a.Password != "" }

// Authenticator turns credentials into a selector.
type Authenticator struct {
	cfg AuthConfig
}

// NewAuthenticator builds an Authenticator.
func NewAuthenticator(cfg AuthConfig) *Authenticator {
	if cfg.DefaultSelector == "" {
		cfg.DefaultSelector = domain.DefaultSelector()
	}
	return &Authenticator{cfg: cfg}
}

// CheckPassword validates only the shared secret, without interpreting the
// username.
//
// The SOCKS5 server needs this at the RFC 1929 step: replying "success" to a
// wrong password and refusing later at request time would leave a client
// believing it had authenticated. The selector is still checked later, so an
// unusable username keeps its specific error message.
func (a *Authenticator) CheckPassword(cred Credentials) error {
	if !a.cfg.passwordSet() {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(a.cfg.Password), []byte(cred.Password)) != 1 {
		return RejectCredentials()
	}
	return nil
}

// Authenticate validates the password and parses the username into a selector.
//
// The username is the selector and the password is only a shared secret; they
// are deliberately independent, which is the whole point of the design.
func (a *Authenticator) Authenticate(cred Credentials) (domain.Selector, error) {
	if err := a.CheckPassword(cred); err != nil {
		return domain.Selector{}, err
	}

	username := cred.Username
	if username == "" {
		if !a.cfg.AllowAnonymous {
			return domain.Selector{}, RejectSelector(fmt.Errorf(
				"a selector username is required, for example global, country-ID, isp-biznet or proxy-1"))
		}
		username = a.cfg.DefaultSelector
	}

	sel, err := domain.ParseSelector(username)
	if err != nil {
		return domain.Selector{}, RejectSelector(err)
	}
	return sel, nil
}
