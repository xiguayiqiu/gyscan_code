package bluez

import (
	"net"
	"syscall"
)

type l2capConn struct {
	conn net.Conn
}

func l2capOpen(addr string, psm uint16) (*l2capConn, error) {
	conn, err := net.Dial("bluetooth", addr)
	if err != nil {
		return nil, err
	}
	return &l2capConn{conn: conn}, nil
}

func (c *l2capConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *l2capConn) Close() error {
	return c.conn.Close()
}

func (c *l2capConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func syscallSetSockOpt(fd, level, opt int, value []byte) error {
	return syscall.SetsockoptString(fd, level, opt, string(value))
}

func dialBluetooth(addr string) (net.Conn, error) {
	return net.Dial("bluetooth", addr)
}

func dialL2CAP(addr string, psm uint16) (net.Conn, error) {
	return net.Dial("bluetooth", addr)
}