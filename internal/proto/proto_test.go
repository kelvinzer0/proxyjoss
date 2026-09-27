package proto

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadGreeting(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		methods []byte
		wantErr bool
	}{
		{
			name:    "no auth",
			wire:    []byte{5, 1, 0},
			methods: []byte{0},
		},
		{
			name:    "user pass",
			wire:    []byte{5, 2, 0, 2},
			methods: []byte{0, 2},
		},
		{
			name:    "wrong version",
			wire:    []byte{4, 1, 0},
			wantErr: true,
		},
		{
			name:    "no methods",
			wire:    []byte{5, 0},
			wantErr: true,
		},
		{
			name:    "truncated",
			wire:    []byte{5, 2, 0},
			wantErr: true,
		},
		{
			name:    "empty",
			wire:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadSocks5Greeting(bytes.NewReader(tc.wire))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ReadSocks5Greeting(% x) = %+v, want an error", tc.wire, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadSocks5Greeting: %v", err)
			}
			for _, m := range tc.methods {
				if !got.HasMethod(m) {
					t.Errorf("HasMethod(%d) = false, want true", m)
				}
			}
		})
	}
}

func TestGreetingHasMethodRejectsAbsent(t *testing.T) {
	greeting, err := ReadSocks5Greeting(bytes.NewReader([]byte{5, 1, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if greeting.HasMethod(2) {
		t.Error("HasMethod(2) = true, want false for a method not offered")
	}
}

func TestWriteMethodReply(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5MethodReply(&buf, AuthNone); err != nil {
		t.Fatal(err)
	}
	// A method reply is exactly two bytes. Sending a full request reply here is
	// the classic SOCKS5 server bug, because the client then reads the first
	// byte of its own request as garbage.
	if got := buf.Bytes(); !bytes.Equal(got, []byte{5, 0}) {
		t.Errorf("WriteSocks5MethodReply = % x, want 05 00", got)
	}

	buf.Reset()
	if err := WriteSocks5MethodReply(&buf, AuthNoAccept); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, []byte{5, 0xff}) {
		t.Errorf("WriteSocks5MethodReply(no accept) = % x, want 05 ff", got)
	}
}

func TestWriteReplyShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5Reply(&buf, ReplySuccess); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	// A request reply is ten bytes with a zero bound address, which is legal
	// and what most clients expect.
	if len(got) != 10 {
		t.Fatalf("WriteSocks5Reply wrote %d bytes, want 10", len(got))
	}
	// Layout: VER, REP, RSV, ATYP, BND.ADDR (4), BND.PORT (2).
	if got[0] != Socks5Version || got[1] != ReplySuccess {
		t.Errorf("header = % x, want %02x %02x", got[:2], Socks5Version, ReplySuccess)
	}
	if got[2] != 0 {
		t.Errorf("reserved byte = %d, want 0", got[2])
	}
	// The bound address is left unspecified. ATYP 1 with 0.0.0.0 is what most
	// servers send, and clients are required to ignore it for CONNECT.
	if got[3] != AddrIPv4 {
		t.Errorf("address type = %d, want %d", got[3], AddrIPv4)
	}
	if !allZero(got[4:]) {
		t.Errorf("bound address and port = % x, want zeros", got[4:])
	}
}

func TestWriteReplyCarriesTheCode(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5Reply(&buf, ReplyHostUnreach); err != nil {
		t.Fatal(err)
	}
	if buf.Bytes()[1] != ReplyHostUnreach {
		t.Errorf("reply code = %d, want %d", buf.Bytes()[1], ReplyHostUnreach)
	}
}

func TestReadSocks5Request(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		host    string
		port    int
		wantErr bool
	}{
		{
			name: "ipv4",
			wire: []byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80},
			host: "1.2.3.4",
			port: 80,
		},
		{
			name: "domain",
			wire: append([]byte{5, 1, 0, 3, 11}, append([]byte("example.com"), 0, 80)...),
			host: "example.com",
			port: 80,
		},
		{
			name: "ipv6",
			wire: append([]byte{5, 1, 0, 4}, append(net.ParseIP("2001:db8::1").To16(), 0, 80)...),
			host: "2001:db8::1",
			port: 80,
		},
		{
			name:    "wrong version",
			wire:    []byte{4, 1, 0, 1, 1, 2, 3, 4, 0, 80},
			wantErr: true,
		},
		{
			name:    "unsupported address type",
			wire:    []byte{5, 1, 0, 9, 1, 2, 3, 4, 0, 80},
			wantErr: true,
		},
		{
			name:    "truncated",
			wire:    []byte{5, 1, 0, 1, 1, 2, 3, 4},
			wantErr: true,
		},
		{
			name:    "oversized domain length",
			wire:    []byte{5, 1, 0, 3, 200, 'a'},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadSocks5Request(bytes.NewReader(tc.wire))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ReadSocks5Request(% x) = %+v, want an error", tc.wire, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadSocks5Request: %v", err)
			}
			if got.Host != tc.host {
				t.Errorf("Host = %q, want %q", got.Host, tc.host)
			}
			if got.Port != tc.port {
				t.Errorf("Port = %d, want %d", got.Port, tc.port)
			}
			if got.Cmd != CmdConnect {
				t.Errorf("Cmd = %d, want CmdConnect", got.Cmd)
			}
		})
	}
}

func TestReadSocks5UserPass(t *testing.T) {
	wire := []byte{1, 5, 'a', 'l', 'i', 'c', 'e', 3, 'p', 'w', 'd'}
	creds, err := ReadSocks5UserPass(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadSocks5UserPass: %v", err)
	}
	if creds.Username != "alice" || creds.Password != "pwd" {
		t.Errorf("creds = %+v, want alice/pwd", creds)
	}
}

func TestReadSocks5UserPassRejectsBadInput(t *testing.T) {
	bad := [][]byte{
		{},                              // empty
		{2, 5, 'a', 'l', 'i', 'c', 'e'}, // wrong subnegotiation version
		{1, 5, 'a'},                     // truncated username
		{1, 200, 'a'},                   // username length out of range
	}
	for _, wire := range bad {
		if _, err := ReadSocks5UserPass(bytes.NewReader(wire)); err == nil {
			t.Errorf("ReadSocks5UserPass(% x) accepted bad input", wire)
		}
	}
}

func TestWriteSocks5UserPassResult(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5UserPassResult(&buf, true); err != nil {
		t.Fatal(err)
	}
	// The subnegotiation reply is two bytes, version 1 then status.
	if got := buf.Bytes(); !bytes.Equal(got, []byte{1, 0}) {
		t.Errorf("success reply = % x, want 01 00", got)
	}
	buf.Reset()
	if err := WriteSocks5UserPassResult(&buf, false); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, []byte{1, 1}) {
		t.Errorf("failure reply = % x, want 01 01", got)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in      string
		host    string
		port    int
		wantErr bool
	}{
		{in: "example.com:443", host: "example.com", port: 443},
		{in: "example.com", host: "example.com", port: 443},
		{in: "example.com:80", host: "example.com", port: 80},
		{in: "1.2.3.4:8080", host: "1.2.3.4", port: 8080},
		// Bracketed IPv6, with and without a port.
		{in: "[2001:db8::1]:443", host: "2001:db8::1", port: 443},
		{in: "[2001:db8::1]", host: "2001:db8::1", port: 443},
		{in: "example.com:0", wantErr: true},
		{in: "example.com:notaport", wantErr: true},
		{in: "example.com:70000", wantErr: true},
		{in: ":443", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			host, port, err := ParseTarget(tc.in, 443)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %s:%d, want an error", tc.in, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tc.in, err)
			}
			if host != tc.host || port != tc.port {
				t.Errorf("ParseTarget(%q) = %s:%d, want %s:%d", tc.in, host, port, tc.host, tc.port)
			}
		})
	}
}

func TestAppendHTTPConnect(t *testing.T) {
	got := AppendConnectRequest(nil, "example.com", 443, "", "proxyjoss")
	text := string(got)
	if !strings.HasPrefix(text, "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Errorf("request line = %q", strings.SplitN(text, "\r\n", 2)[0])
	}
	if !strings.Contains(text, "Host: example.com:443\r\n") {
		t.Error("the Host header is missing or wrong")
	}
	if !strings.Contains(text, "User-Agent: proxyjoss\r\n") {
		t.Error("the User-Agent header is missing")
	}
	if strings.Contains(text, "SNI:") {
		t.Error("an SNI header was sent although none was configured")
	}
	if !strings.HasSuffix(text, "\r\n\r\n") {
		t.Error("the request does not end with a blank line")
	}

	// A terminator in front of the origin needs the real name to route, so the
	// SNI header is sent when one is known.
	withSNI := string(AppendConnectRequest(nil, "1.2.3.4", 443, "example.com", ""))
	if !strings.Contains(withSNI, "SNI: example.com\r\n") {
		t.Errorf("the SNI header is missing: %q", withSNI)
	}
	if !strings.Contains(withSNI, "User-Agent: proxyjoss\r\n") {
		t.Error("a blank user agent did not fall back to a default")
	}
}

func TestReadConnectResponse(t *testing.T) {
	ok := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if err := ReadConnectResponse(bufio.NewReader(strings.NewReader(ok))); err != nil {
		t.Errorf("a 200 was rejected: %v", err)
	}
	// A non-200 must be an error, or the client would think it has a tunnel.
	for _, status := range []string{"403 Forbidden", "407 Proxy Authentication Required", "502 Bad Gateway"} {
		wire := "HTTP/1.1 " + status + "\r\n\r\n"
		if err := ReadConnectResponse(bufio.NewReader(strings.NewReader(wire))); err == nil {
			t.Errorf("ReadConnectResponse accepted %q", status)
		}
	}
}

func TestAppendPlainHTTPGet(t *testing.T) {
	got := AppendPlainHTTPGet(nil, "example.com", 80, "/health", "ua")
	text := string(got)
	if !strings.HasPrefix(text, "GET /health HTTP/1.1\r\n") {
		t.Errorf("request line = %q", strings.SplitN(text, "\r\n", 2)[0])
	}
	if !strings.Contains(text, "Host: example.com\r\n") {
		t.Errorf("the Host header should omit the default port, got %q", text)
	}
	// A path is required, or the request line is malformed.
	if got := AppendPlainHTTPGet(nil, "example.com", 80, "", "ua"); !strings.Contains(string(got), "GET / ") {
		t.Errorf("an empty path became %q", strings.SplitN(string(got), "\r\n", 2)[0])
	}
}

func TestReadHTTPStatus(t *testing.T) {
	tests := []struct {
		name    string
		wire    string
		want    int
		wantErr bool
	}{
		{name: "ok", wire: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", want: 200},
		{name: "not found", wire: "HTTP/1.1 404 Not Found\r\n\r\n", want: 404},
		{name: "server error", wire: "HTTP/1.1 503 Service Unavailable\r\n\r\n", want: 503},
		{name: "no reason phrase", wire: "HTTP/1.1 200\r\n\r\n", want: 200},
		{name: "garbage", wire: "not http at all\r\n\r\n", wantErr: true},
		// A complete status line is enough, since that is all a probe needs.
		{name: "status line only", wire: "HTTP/1.1 200 OK\r\n", want: 200},
		{name: "truncated status line", wire: "HTTP/1.1 20", wantErr: true},
		{name: "empty", wire: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadHTTPStatus(strings.NewReader(tc.wire))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ReadHTTPStatus(%q) = %d, want an error", tc.wire, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadHTTPStatus: %v", err)
			}
			if got != tc.want {
				t.Errorf("ReadHTTPStatus = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSetDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// A zero deadline means "no deadline", which SetDeadline must support so a
	// tunnel can run indefinitely after the handshake.
	if err := SetDeadline(client, time.Time{}, time.Second); err != nil {
		t.Fatalf("SetDeadline with a zero time: %v", err)
	}
	deadline := time.Now().Add(time.Hour)
	if err := SetDeadline(client, deadline, time.Second); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	// An explicitly zero timeout with a context deadline must not be mistaken
	// for "no deadline".
	if err := SetDeadline(client, time.Now().Add(time.Hour), 0); err != nil {
		t.Fatalf("SetDeadline with a zero timeout: %v", err)
	}
}

// A reader that returns one byte at a time is the case that catches codecs
// which assume a whole message arrives in a single read.
type dribbleReader struct{ r io.Reader }

func (d dribbleReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return d.r.Read(p)
}

func TestReadersHandlePartialReads(t *testing.T) {
	greeting := []byte{5, 2, 0, 2}
	if _, err := ReadSocks5Greeting(dribbleReader{bytes.NewReader(greeting)}); err != nil {
		t.Errorf("ReadSocks5Greeting with dribbled input: %v", err)
	}
	request := []byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}
	if _, err := ReadSocks5Request(dribbleReader{bytes.NewReader(request)}); err != nil {
		t.Errorf("ReadSocks5Request with dribbled input: %v", err)
	}
	creds := []byte{1, 5, 'a', 'l', 'i', 'c', 'e', 3, 'p', 'w', 'd'}
	if _, err := ReadSocks5UserPass(dribbleReader{bytes.NewReader(creds)}); err != nil {
		t.Errorf("ReadSocks5UserPass with dribbled input: %v", err)
	}
}

// BufferedConn must not lose bytes read past a message boundary. An upstream
// that sends its reply and the first tunnel payload in one write leaves the
// payload in the buffer, and reading it from the raw connection would drop it.
func TestBufferedConnKeepsBufferedBytes(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	wire.WriteString("PAYLOAD-AFTER-THE-REPLY")

	client, server := net.Pipe()
	go func() {
		_, _ = server.Write(wire.Bytes())
		_ = server.Close()
	}()

	reader := bufio.NewReader(client)
	if err := ReadConnectResponse(reader); err != nil {
		t.Fatalf("ReadConnectResponse: %v", err)
	}
	conn := NewBufferedConn(client, reader)
	defer conn.Close()

	const want = "PAYLOAD-AFTER-THE-REPLY"
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading the buffered payload: %v", err)
	}
	if string(buf) != want {
		t.Errorf("payload = %q, want %q", buf, want)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestAppendSocks5UserPassIsWellFormed(t *testing.T) {
	tests := []struct {
		username string
		password string
		want     []byte
	}{
		// The password length byte is present even when empty. A message that
		// stops after the username leaves a strict server waiting forever.
		{"", "", []byte{0x01, 0x00, 0x00}},
		{"alice", "", []byte{0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x00}},
		{"alice", "pw", []byte{0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x02, 'p', 'w'}},
	}
	for _, tc := range tests {
		got := AppendSocks5UserPass(nil, tc.username, tc.password)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("AppendSocks5UserPass(%q, %q) = % x, want % x", tc.username, tc.password, got, tc.want)
		}
		// Anything this writes must be readable by a strict server.
		creds, err := ReadSocks5UserPass(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("ReadSocks5UserPass(% x): %v", got, err)
		}
		if creds.Username != tc.username || creds.Password != tc.password {
			t.Errorf("round trip gave %q/%q, want %q/%q", creds.Username, creds.Password, tc.username, tc.password)
		}
	}
}

func TestAppendSocks5UserPassBoundsOverlongFields(t *testing.T) {
	// A field longer than a byte cannot be encoded. It is cut rather than
	// overflowing into a wrong length, so the server rejects it outright
	// instead of reading the wrong password.
	long := strings.Repeat("u", 300)
	got := AppendSocks5UserPass(nil, long, "pw")
	if got[1] != 255 {
		t.Errorf("username length byte = %d, want 255", got[1])
	}
	creds, err := ReadSocks5UserPass(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("the truncated message should still parse: %v", err)
	}
	if len(creds.Username) != 255 {
		t.Errorf("username length = %d, want 255", len(creds.Username))
	}
}

func TestAppendSocks5UserPassAppendsToExistingBytes(t *testing.T) {
	prefix := []byte{0xde, 0xad}
	got := AppendSocks5UserPass(prefix, "u", "p")
	if !bytes.Equal(got, []byte{0xde, 0xad, 0x01, 0x01, 'u', 0x01, 'p'}) {
		t.Errorf("AppendSocks5UserPass did not append: % x", got)
	}
}
