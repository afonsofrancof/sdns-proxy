package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/afonsofrancof/sdns-proxy/internal/protocols/do53"
	"github.com/afonsofrancof/sdns-proxy/internal/protocols/doh"
	"github.com/afonsofrancof/sdns-proxy/internal/protocols/doq"
	"github.com/afonsofrancof/sdns-proxy/internal/protocols/dot"
	"github.com/miekg/dns"
)

type DNSClient interface {
	Query(domain string, queryType uint16) (*dns.Msg, error)
	Close()
}

type Options struct {
	DNSSEC bool
}

// New creates a DNS client based on the upstream string
func New(upstream string, opts Options) (DNSClient, error) {
	// Try to parse as URL first
	parsedURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream format: %w", err)
	}

	// If it has a scheme, treat it as a full URL
	if parsedURL.Scheme != "" {
		return createClientFromURL(parsedURL, opts)
	}

	// No scheme - treat as plain DNS address (IP or hostname with optional port)
	return createClientFromPlainAddress(upstream, opts)
}

func createClientFromURL(parsedURL *url.URL, opts Options) (DNSClient, error) {
	scheme := strings.ToLower(parsedURL.Scheme)
	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in upstream URL")
	}

	port := parsedURL.Port()
	if port == "" {
		port = getDefaultPort(scheme)
	}

	path := parsedURL.Path
	if path == "" {
		path = getDefaultPath(scheme)
	}

	return createClient(scheme, host, port, path, opts)
}

func createClientFromPlainAddress(address string, opts Options) (DNSClient, error) {
	var host, port string
	var err error

	host, port, err = net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "53"
	}

	if host == "" {
		return nil, fmt.Errorf("empty host in address: %s", address)
	}

	return createClient("", host, port, "", opts)
}

func getDefaultPort(scheme string) string {
	switch scheme {
	case "https", "doh", "doh3":
		return "443"
	case "tls", "dot":
		return "853"
	case "quic", "doq":
		return "853"
	default:
		return "53"
	}
}

func getDefaultPath(scheme string) string {
	switch scheme {
	case "https", "doh", "doh3":
		return "/dns-query"
	default:
		return ""
	}
}

func createClient(scheme, host, port, path string, opts Options) (DNSClient, error) {
	switch scheme {
	case "udp", "tcp", "do53", "":
		config := do53.Config{
			HostAndPort: net.JoinHostPort(host, port),
			DNSSEC:      opts.DNSSEC,
		}
		return do53.New(config)

	case "http", "doh":
		config := doh.Config{
			Host:   host,
			Port:   port,
			Path:   path,
			DNSSEC: opts.DNSSEC,
			HTTP3:  false,
		}
		return doh.New(config)

	case "https", "doh3":
		config := doh.Config{
			Host:   host,
			Port:   port,
			Path:   path,
			DNSSEC: opts.DNSSEC,
			HTTP3:  true,
		}
		return doh.New(config)

	case "tls", "dot":
		config := dot.Config{
			Host:   host,
			Port:   port,
			DNSSEC: opts.DNSSEC,
		}
		return dot.New(config)

	case "doq": // DNS over QUIC
		config := doq.Config{
			Host:   host,
			Port:   port,
			DNSSEC: opts.DNSSEC,
		}
		return doq.New(config)

	default:
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}
}
