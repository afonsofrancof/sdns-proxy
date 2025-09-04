// internal/client/client.go
package client

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/afonsofrancof/sdns-perf/internal/protocols/doh"
	// "github.com/afonsofrancof/sdns-perf/internal/protocols/doq"
	// "github.com/afonsofrancof/sdns-perf/internal/protocols/dot"

	"github.com/miekg/dns"
)

// DNSClient defines the interface that all specific protocol clients must implement.
type DNSClient interface {
	Query(domain string, queryType uint16) (*dns.Msg, error)
	Close()
}

// Options holds common configuration options for creating any DNS client.
type Options struct {
	Timeout    time.Duration
	DNSSEC     bool
	KeyLogPath string // Path for TLS key logging
}

type protocolType int

const (
	protoUnknown protocolType = iota
	protoDo53
	protoDoT
	protoDoH
	protoDoH3
	protoDoQ
)

// config holds the parsed details of an upstream server string.
// This is internal to the client package.
type config struct {
	original string
	protocol protocolType
	host     string
	port     string
	path     string
}

// parseUpstream takes a user-provided upstream string and attempts to determine
// the protocol, host, port, and path. (Internal helper)
func parseUpstream(upstreamStr string) (config, error) {
	cfg := config{original: upstreamStr, protocol: protoUnknown}

	// Try parsing as a full URL first
	parsedURL, err := url.Parse(upstreamStr)
	if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
		cfg.host = parsedURL.Hostname()
		cfg.port = parsedURL.Port()
		cfg.path = parsedURL.Path
		if cfg.path == "" {
			cfg.path = "/" // Default path
		}

		switch strings.ToLower(parsedURL.Scheme) {
		case "https", "doh":
			cfg.protocol = protoDoH
			if cfg.port == "" {
				cfg.port = "443"
			}
		case "h3", "doh3":
			cfg.protocol = protoDoH3
			if cfg.port == "" {
				cfg.port = "443"
			}
		case "tls", "dot":
			cfg.protocol = protoDoT
			if cfg.port == "" {
				cfg.port = "853"
			}
		case "quic", "doq":
			cfg.protocol = protoDoQ
			if cfg.port == "" {
				cfg.port = "853"
			}
		case "udp", "do53":
			cfg.protocol = protoDo53
			if cfg.port == "" {
				cfg.port = "53"
			}
		default:
			return cfg, fmt.Errorf("unsupported URL scheme: %q", parsedURL.Scheme)
		}
		return cfg, nil
	}

	// If not a valid URL or no scheme, assume plain DNS (Do53 UDP)
	cfg.protocol = protoDo53
	host, port, err := net.SplitHostPort(upstreamStr)
	if err == nil {
		cfg.host = host
		cfg.port = port
		if _, pErr := strconv.Atoi(port); pErr != nil {
			return cfg, fmt.Errorf("invalid port %q in upstream %q: %w", port, upstreamStr, pErr)
		}
	} else {
		cfg.host = upstreamStr
		cfg.port = "53"
		// Basic check for likely IPv6 without brackets and port
		if strings.Contains(cfg.host, ":") && !strings.Contains(cfg.host, "[") {
			_, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.host, cfg.port))
			if resolveErr != nil {
				return cfg, fmt.Errorf("invalid upstream format; could not parse %q as host:port or resolve as host with default port 53: %w", upstreamStr, err)
			}
		}
	}

	if cfg.host == "" {
		return cfg, fmt.Errorf("could not extract host from upstream: %q", upstreamStr)
	}

	return cfg, nil
}

// New creates the appropriate DNS client based on the upstream string format.
// It returns an uninitialized client (connections are lazy).
func New(upstreamStr string, opts Options) (DNSClient, error) {
	cfg, err := parseUpstream(upstreamStr)
	if err != nil {
		return nil, fmt.Errorf("client: failed to parse upstream %q: %w", upstreamStr, err)
	}

	var client DNSClient
	var clientErr error

	switch cfg.protocol {
	case protoDo53:
		// Ensure do53.New matches this signature
		config := do53.Config{HostAndPort: net.JoinHostPort(cfg.host, cfg.port), DNSSEC: false}
		client, clientErr = do53.New(config)

	case protoDoH:
		// Ensure doh.New matches this signature
		config := doh.Config{Host: cfg.host, Port: cfg.port, Path: cfg.path, DNSSEC: false}
		client, clientErr = doh.New(config)

	case protoDoT:
		// Ensure dot.New matches this signature
		// client, clientErr = dot.New(cfg.hostPort(), opts.Timeout, opts.DNSSEC, opts.KeyLogPath)
		// if clientErr == nil && client == nil {
		// 	clientErr = fmt.Errorf("client: DoT package returned nil client without error")
		// }

	case protoDoQ:
		// Ensure doq.New matches this signature
		// client, clientErr = doq.New(cfg.hostPort(), cfg.path, opts.Timeout, opts.DNSSEC, opts.KeyLogPath)
		// if clientErr == nil && client == nil {
		// 	clientErr = fmt.Errorf("client: DoQ package returned nil client without error")
		// }

	case protoDoH3:
		// Decide on DoH3 handling (fallback or error)
		// Fallback example:
		// fmt.Fprintf(os.Stderr, "Warning: DoH3 protocol (h3://) detected for %s. Attempting connection using standard DoH (HTTPS).\n", cfg.original)
		// client, clientErr = doh.New(cfg.hostPort(), cfg.path, opts.Timeout, opts.DNSSEC, opts.KeyLogPath)
		// Error example:
		// clientErr = fmt.Errorf("client: DoH3 protocol (h3://) is not yet supported")

	default:
		clientErr = fmt.Errorf("client: unknown or unsupported protocol detected for upstream: %s", upstreamStr)
	}

	if clientErr != nil {
		return nil, fmt.Errorf("client: failed to create client for %s: %w", upstreamStr, clientErr)
	}
	if client == nil {
		// Should be caught by clientErr checks above, but as a safeguard
		return nil, fmt.Errorf("client: internal error - nil client returned for %s", upstreamStr)
	}

	return client, nil
}

// Helper function to close key log writer if needed (can be used by specific clients)
func CloseKeyLogWriter(w io.WriteCloser) error {
	if w != nil {
		return w.Close()
	}
	return nil
}
