package anytls

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	N "github.com/sagernet/sing/common/network"
)

type countingConn struct {
	net.Conn
	readBytes    atomic.Int64
	writtenBytes atomic.Int64
}

func newCountingConn(conn net.Conn) *countingConn {
	return &countingConn{Conn: conn}
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.readBytes.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.writtenBytes.Add(int64(n))
	return n, err
}

func (c *countingConn) BytesRead() int64 {
	return c.readBytes.Load()
}

func (c *countingConn) BytesWritten() int64 {
	return c.writtenBytes.Load()
}

func relay(ctx context.Context, inbound net.Conn, outbound net.Conn, onClose N.CloseHandlerFunc) {
	var once sync.Once
	done := make(chan struct{})
	closeAll := func(err error) {
		once.Do(func() {
			close(done)
			if onClose != nil {
				onClose(err)
			}
			_ = inbound.Close()
			_ = outbound.Close()
		})
	}

	go func() {
		select {
		case <-ctx.Done():
			closeAll(ctx.Err())
		case <-done:
		}
	}()

	go proxyCopy(inbound, outbound, closeAll)
	go proxyCopy(outbound, inbound, closeAll)
}

func proxyCopy(dst net.Conn, src net.Conn, closeAll func(error)) {
	_, err := io.Copy(dst, src)
	closeAll(err)
}
