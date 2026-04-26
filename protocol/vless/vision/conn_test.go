package vision

import (
	"net"
	"strings"
	"testing"
	"time"
)

type stubConn struct{}

func (stubConn) Read(p []byte) (int, error) {
	return 0, nil
}

func (stubConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (stubConn) Close() error {
	return nil
}

func (stubConn) LocalAddr() net.Addr {
	return nil
}

func (stubConn) RemoteAddr() net.Addr {
	return nil
}

func (stubConn) SetDeadline(time.Time) error {
	return nil
}

func (stubConn) SetReadDeadline(time.Time) error {
	return nil
}

func (stubConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestWriteReturnsErrorForUnsupportedTLSConnType(t *testing.T) {
	overlay := stubConn{}
	conn := &Conn{
		Conn:          overlay,
		overlayConn:   overlay,
		tlsConn:       stubConn{},
		userUUID:      make([]byte, 16),
		needHandshake: true,
	}
	conn.writer = &writeWrapper{vision: conn}

	err := conn.write(nil)
	if err == nil {
		t.Fatal("expected unsupported tls connection type error")
	}
	if !strings.Contains(err.Error(), "unsupported outer tls connection type") {
		t.Fatalf("unexpected error: %v", err)
	}
}
