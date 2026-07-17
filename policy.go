package anytls

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

var privateDestinationPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

func (lw *ListenerWrapper) compileCIDRPolicies() error {
	allow, err := parseCIDRPrefixes("allow_cidr", lw.AllowCIDRs)
	if err != nil {
		return err
	}
	deny, err := parseCIDRPrefixes("deny_cidr", lw.DenyCIDRs)
	if err != nil {
		return err
	}
	lw.allowCIDRPrefixes = allow
	lw.denyCIDRPrefixes = deny
	return nil
}

func parseCIDRPrefixes(name string, cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid %s %q: %w", name, cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (h *directTCPHandler) validateStreamDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	return h.validateDestination(ctx, destination)
}

func (h *directTCPHandler) validatePacketDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	return h.validateDestination(ctx, destination)
}

func (h *directTCPHandler) validateDestination(ctx context.Context, destination M.Socksaddr) ([]M.Socksaddr, error) {
	if !destination.IsValid() || destination.Port == 0 {
		return nil, fmt.Errorf("%w", errInvalidDestination)
	}
	if err := h.validateNameAndPortPolicy(destination); err != nil {
		return nil, err
	}
	if h.config.AllowPrivateTargets && !h.needsCIDRPolicy() {
		// No CIDR policy applies, but still resolve here so the Outbound
		// contract holds unconditionally: outbounds always receive an
		// already-resolved "ip:port", never a domain. Only the policy check
		// is skipped, not resolution through the selected outbound.
		return h.resolveDestination(ctx, destination)
	}
	resolvedDestinations, err := h.resolveDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if err := h.validateResolvedDestinationPolicy(destination, resolvedDestinations); err != nil {
		return nil, err
	}
	return resolvedDestinations, nil
}

func (h *directTCPHandler) validateNameAndPortPolicy(destination M.Socksaddr) error {
	if containsPort(h.config.DenyPorts, destination.Port) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	if len(h.config.AllowPorts) > 0 && !containsPort(h.config.AllowPorts, destination.Port) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	if destination.Fqdn == "" {
		return nil
	}
	if matchesDomainPolicy(h.config.DenyDomains, destination.Fqdn) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	if len(h.config.AllowDomains) > 0 && !matchesDomainPolicy(h.config.AllowDomains, destination.Fqdn) {
		return fmt.Errorf("%w: %s", errDestinationPolicyDenied, destination.String())
	}
	return nil
}

func (h *directTCPHandler) needsCIDRPolicy() bool {
	return len(h.config.AllowCIDRs) > 0 || len(h.config.DenyCIDRs) > 0 || !h.config.AllowPrivateTargets
}

func (h *directTCPHandler) validateResolvedDestinationPolicy(original M.Socksaddr, destinations []M.Socksaddr) error {
	for _, destination := range destinations {
		if matchesCIDRPolicy(h.config.denyCIDRPrefixes, destination.Addr) {
			return fmt.Errorf("%w: %s resolves to %s", errDestinationPolicyDenied, original.String(), destination.Addr.String())
		}
	}
	for _, destination := range destinations {
		private := isPrivateDestination(destination)
		allowedCIDR := matchesCIDRPolicy(h.config.allowCIDRPrefixes, destination.Addr)
		if private && !h.config.AllowPrivateTargets && !allowedCIDR {
			return fmt.Errorf("%w: %s resolves to %s", errPrivateDestinationDenied, original.String(), destination.Addr.String())
		}
		if len(h.config.allowCIDRPrefixes) > 0 && !allowedCIDR {
			return fmt.Errorf("%w: %s resolves to %s", errDestinationPolicyDenied, original.String(), destination.Addr.String())
		}
	}
	return nil
}

func containsPort(ports []uint16, port uint16) bool {
	return slices.Contains(ports, port)
}

func matchesCIDRPolicy(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func matchesDomainPolicy(patterns []string, domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for _, pattern := range patterns {
		pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
		switch {
		case pattern == domain:
			return true
		case strings.HasPrefix(pattern, ".") && strings.HasSuffix(domain, pattern):
			return true
		case strings.HasPrefix(pattern, "*.") && strings.HasSuffix(domain, strings.TrimPrefix(pattern, "*")):
			return true
		}
	}
	return false
}

func isPrivateDestination(destination M.Socksaddr) bool {
	if !destination.Addr.IsValid() {
		return false
	}
	addr := destination.Addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	for _, prefix := range privateDestinationPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
