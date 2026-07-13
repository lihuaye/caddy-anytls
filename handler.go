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

type dialResult struct {
	conn net.Conn
	err  error
}

type handshakeFailureReporter interface {
	HandshakeFailure(error) error
}

func (h *directTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	startedAt := time.Now()
	connectionID := connectionIDFromContext(ctx)
	h.config.updateSessionUser(connectionID, userFromContext(ctx))
	if !h.config.acquireStream(connectionID) {
		err := fmt.Errorf("%w", errStreamLimitExceeded)
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		reportHandshakeFailure(conn, err)
		if onClose != nil {
			onClose(err)
		}
		_ = conn.Close()
		return
	}
	inbound := conn
	var inboundCounter *countingConn
	var outboundCounter *countingConn
	if h.config.logger.Core().Enabled(zap.DebugLevel) {
		inboundCounter = newCountingConn(conn)
		inbound = inboundCounter
	}
	closeOnce := N.OnceClose(func(err error) {
		h.config.releaseStream(connectionID)
		if inboundCounter != nil && outboundCounter != nil {
			h.config.logger.Debug("anytls relay closed",
				zap.Uint64("connection_id", connectionID),
				zap.String("event", "anytls_relay"),
				zap.String("outcome", "closed"),
				zap.String("protocol", "tcp"),
				zap.String("user", userFromContext(ctx)),
				zap.String("source", source.String()),
				zap.String("destination", destination.String()),
				zap.Int64("bytes_from_client", inboundCounter.BytesRead()),
				zap.Int64("bytes_to_client", inboundCounter.BytesWritten()),
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
		reportHandshakeFailure(conn, err)
		closeOnce(err)
		_ = conn.Close()
		return
	}
	outboundRelay := outbound
	if inboundCounter != nil {
		outboundCounter = newCountingConn(outbound)
		outboundRelay = outboundCounter
	}

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "tcp"),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, inbound, outboundRelay, closeOnce)
}

func (h *directTCPHandler) handleUDPOverTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, connectionID uint64, closeOnce N.CloseHandlerFunc) {
	request, err := h.readUDPOverTCPRequest(ctx, conn, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		reportHandshakeFailure(conn, err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	packetConn, err := h.listenPacketContext(ctx)
	if err != nil {
		h.logOutboundFailure(connectionID, source, request.Destination, startedAt, userFromContext(ctx), err)
		reportHandshakeFailure(conn, err)
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
	if timeout := time.Duration(h.config.ConnectTimeout); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	resolvedDestinations, err := h.validateStreamDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	resolvedDestinations = interleaveAddressFamilies(resolvedDestinations)

	dialer := &net.Dialer{}
	results := make(chan dialResult)
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	launchDial := func(resolvedDestination M.Socksaddr) {
		go func() {
			var conn net.Conn
			var dialErr error
			if h.config.dialFunc != nil {
				conn, dialErr = h.config.dialFunc(dialCtx, "tcp", resolvedDestination.String())
			} else {
				conn, dialErr = dialer.DialContext(dialCtx, "tcp", resolvedDestination.String())
			}
			if dialErr != nil {
				dialErr = fmt.Errorf("dial %s: %w", resolvedDestination.String(), dialErr)
			}
			results <- dialResult{conn: conn, err: dialErr}
		}()
	}

	const fallbackDelay = 250 * time.Millisecond
	next := 1
	inFlight := 1
	launchDial(resolvedDestinations[0])
	fallbackTimer := time.NewTimer(fallbackDelay)
	defer fallbackTimer.Stop()
	fallbackTimerC := fallbackTimer.C
	if len(resolvedDestinations) == 1 {
		fallbackTimerC = nil
	}

	var errs []error
	for inFlight > 0 {
		select {
		case result := <-results:
			inFlight--
			if result.err == nil && result.conn != nil {
				cancel()
				go drainDialResults(results, inFlight)
				return result.conn, nil
			}
			if result.err == nil {
				result.err = errors.New("dial returned a nil connection")
			}
			errs = append(errs, result.err)
			if next < len(resolvedDestinations) {
				launchDial(resolvedDestinations[next])
				next++
				inFlight++
				fallbackTimer.Reset(fallbackDelay)
				if next < len(resolvedDestinations) {
					fallbackTimerC = fallbackTimer.C
				} else {
					fallbackTimerC = nil
				}
			}
		case <-fallbackTimerC:
			launchDial(resolvedDestinations[next])
			next++
			inFlight++
			if next < len(resolvedDestinations) {
				fallbackTimer.Reset(fallbackDelay)
			} else {
				fallbackTimerC = nil
			}
		case <-ctx.Done():
			cancel()
			go drainDialResults(results, inFlight)
			return nil, errors.Join(append(errs, ctx.Err())...)
		}
	}
	return nil, errors.Join(errs...)
}

func drainDialResults(results <-chan dialResult, remaining int) {
	for range remaining {
		result := <-results
		if result.conn != nil {
			_ = result.conn.Close()
		}
	}
}

func interleaveAddressFamilies(destinations []M.Socksaddr) []M.Socksaddr {
	if len(destinations) < 2 {
		return destinations
	}
	firstIsIPv6 := destinations[0].Addr.Is6()
	preferred := make([]M.Socksaddr, 0, len(destinations))
	alternate := make([]M.Socksaddr, 0, len(destinations))
	for _, destination := range destinations {
		if destination.Addr.Is6() == firstIsIPv6 {
			preferred = append(preferred, destination)
		} else {
			alternate = append(alternate, destination)
		}
	}
	interleaved := make([]M.Socksaddr, 0, len(destinations))
	for len(preferred) > 0 || len(alternate) > 0 {
		if len(preferred) > 0 {
			interleaved = append(interleaved, preferred[0])
			preferred = preferred[1:]
		}
		if len(alternate) > 0 {
			interleaved = append(interleaved, alternate[0])
			alternate = alternate[1:]
		}
	}
	return interleaved
}

func reportHandshakeFailure(conn net.Conn, err error) {
	if reporter, ok := conn.(handshakeFailureReporter); ok {
		_ = reporter.HandshakeFailure(err)
	}
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
