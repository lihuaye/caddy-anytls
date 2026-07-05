package anytls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"go.uber.org/zap"
)

type directTCPHandler struct {
	config *ListenerWrapper
}

func (h *directTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	startedAt := time.Now()
	connectionID := connectionIDFromContext(ctx)
	h.config.updateSessionUser(connectionID, userFromContext(ctx))
	inbound := newCountingConn(conn)
	var outboundCounter *countingConn
	closeOnce := N.OnceClose(func(err error) {
		if outboundCounter != nil {
			h.config.logger.Debug("anytls relay closed",
				zap.Uint64("connection_id", connectionID),
				zap.String("event", "anytls_relay"),
				zap.String("outcome", "closed"),
				zap.String("protocol", "tcp"),
				zap.String("user", userFromContext(ctx)),
				zap.String("source", source.String()),
				zap.String("destination", destination.String()),
				zap.Int64("bytes_from_client", inbound.BytesRead()),
				zap.Int64("bytes_to_client", inbound.BytesWritten()),
				zap.Int64("bytes_from_target", outboundCounter.BytesRead()),
				zap.Int64("bytes_to_target", outboundCounter.BytesWritten()),
				zap.Duration("duration", time.Since(startedAt)),
			)
		}
		if onClose != nil {
			onClose(err)
		}
	})

	if isUDPOverTCPDestination(destination) {
		h.handleUDPOverTCP(ctx, conn, source, destination, startedAt, connectionID, closeOnce)
		return
	}

	outbound, err := h.dialContext(ctx, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}
	outboundCounter = newCountingConn(outbound)

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "tcp"),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, inbound, outboundCounter, closeOnce)
}

func (h *directTCPHandler) handleUDPOverTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, connectionID uint64, closeOnce N.CloseHandlerFunc) {
	request, err := h.readUDPOverTCPRequest(ctx, conn, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	packetConn, err := h.listenPacketContext(ctx)
	if err != nil {
		h.logOutboundFailure(connectionID, source, request.Destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	uotConn := uot.NewConn(conn, *request)
	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "udp_over_tcp_v2"),
		zap.Bool("uot_is_connect", request.IsConnect),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", request.Destination.String()),
	)

	relayUDPOverTCP(ctx, uotConn, packetConn, h.preparePacketDestination, closeOnce)
}

func (h *directTCPHandler) dialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	resolvedDestinations, err := h.validateStreamDestination(ctx, destination)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(h.config.ConnectTimeout),
	}
	var errs []error
	for _, resolvedDestination := range resolvedDestinations {
		var conn net.Conn
		if h.config.dialFunc != nil {
			conn, err = h.config.dialFunc(ctx, "tcp", resolvedDestination.String())
		} else {
			conn, err = dialer.DialContext(ctx, "tcp", resolvedDestination.String())
		}
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("dial %s: %w", resolvedDestination.String(), err))
	}
	return nil, errors.Join(errs...)
}

func (h *directTCPHandler) listenPacketContext(ctx context.Context) (net.PacketConn, error) {
	if h.config.listenPacketFunc != nil {
		return h.config.listenPacketFunc(ctx, "udp", "")
	}

	listenConfig := net.ListenConfig{}
	return listenConfig.ListenPacket(ctx, "udp", "")
}

func (h *directTCPHandler) readUDPOverTCPRequest(ctx context.Context, conn net.Conn, destination M.Socksaddr) (*uot.Request, error) {
	switch destination.Fqdn {
	case uot.MagicAddress:
		request, err := uot.ReadRequest(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidUDPOverTCPRequest, err)
		}
		if request.IsConnect {
			if _, err := h.validatePacketDestination(ctx, request.Destination); err != nil {
				return nil, err
			}
		}
		return request, nil
	case uot.LegacyMagicAddress:
		return &uot.Request{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedUDPOverTCP, destination.String())
	}
}

func (h *directTCPHandler) preparePacketDestination(ctx context.Context, destination M.Socksaddr) (net.Addr, error) {
	resolvedDestinations, err := h.validatePacketDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	return resolveUDPAddr(resolvedDestinations[0])
}

func (h *directTCPHandler) resolveDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	if destination.Addr.IsValid() {
		return []M.Socksaddr{destination}, nil
	}
	resolveFunc := h.config.resolveFunc
	if resolveFunc == nil {
		resolver := net.DefaultResolver
		resolveFunc = resolver.LookupNetIP
	}
	addresses, err := resolveFunc(ctx, "ip", destination.Fqdn)
	if err != nil {
		return nil, fmt.Errorf("resolve destination %s: %w", destination.String(), err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve destination %s: no addresses", destination.String())
	}
	destinations := make([]M.Socksaddr, 0, len(addresses))
	for _, addr := range addresses {
		destinations = append(destinations, M.Socksaddr{Addr: addr, Port: destination.Port})
	}
	return destinations, nil
}

func (h *directTCPHandler) logOutboundFailure(connectionID uint64, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, user string, err error) {
	protocol := "tcp"
	if isUDPOverTCPDestination(destination) {
		protocol = "udp_over_tcp_v2"
	}
	h.config.logger.Warn("anytls outbound dial failed",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_outbound"),
		zap.String("outcome", "rejected"),
		zap.String("reason", dialFailureReason(err)),
		zap.String("protocol", protocol),
		zap.String("user", user),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
		zap.Duration("duration", time.Since(startedAt)),
		zap.Error(err),
	)
}

func isUDPOverTCPDestination(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}
