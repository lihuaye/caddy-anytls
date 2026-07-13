package anytls

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func relayUDPOverTCP(ctx context.Context, inbound *uot.Conn, outbound net.PacketConn, prepareDestination func(context.Context, M.Socksaddr) (net.Addr, error), onClose N.CloseHandlerFunc) {
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

	go func() {
		closeAll(proxyUOTToPacket(ctx, inbound, outbound, prepareDestination))
	}()
	go func() {
		closeAll(proxyPacketToUOT(outbound, inbound))
	}()
}

func proxyUOTToPacket(ctx context.Context, inbound *uot.Conn, outbound net.PacketConn, prepareDestination func(context.Context, M.Socksaddr) (net.Addr, error)) error {
	packet := buf.NewPacket()
	defer packet.Release()
	type cacheEntry struct {
		addr      net.Addr
		expiresAt time.Time
	}
	const maxCachedDestinations = 256
	destinationCache := make(map[string]cacheEntry)

	for {
		packet.Reset()
		destination, err := inbound.ReadPacket(packet)
		if err != nil {
			return err
		}
		key := destination.String()
		cached, ok := destinationCache[key]
		if !ok || time.Now().After(cached.expiresAt) {
			addr, err := prepareDestination(ctx, destination)
			if err != nil {
				return err
			}
			if len(destinationCache) >= maxCachedDestinations {
				clear(destinationCache)
			}
			cached = cacheEntry{addr: addr, expiresAt: time.Now().Add(30 * time.Second)}
			destinationCache[key] = cached
		}
		if _, err := outbound.WriteTo(packet.Bytes(), cached.addr); err != nil {
			return err
		}
	}
}

func proxyPacketToUOT(inbound net.PacketConn, outbound *uot.Conn) error {
	packet := buf.NewPacket()
	defer packet.Release()

	for {
		packet.Reset()
		_, addr, err := packet.ReadPacketFrom(inbound)
		if err != nil {
			return err
		}
		if err := outbound.WritePacket(packet, M.SocksaddrFromNet(addr)); err != nil {
			return err
		}
	}
}

func resolveUDPAddr(destination M.Socksaddr) (net.Addr, error) {
	if destination.Addr.IsValid() {
		return destination.UDPAddr(), nil
	}
	return net.ResolveUDPAddr("udp", destination.String())
}
