package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/dnscrypt"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/doh"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/doq"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/dot"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/dotcp"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/doudp"
	"github.com/miekg/dns"
)

type DNSClient interface {
	Query(msg *dns.Msg) (sent *dns.Msg, resp *dns.Msg, err error)
	Close()
}

type Options struct {
	DNSSEC              bool
	AuthoritativeDNSSEC bool
	ValidateOnly        bool
	StrictValidation    bool
	KeepAlive           bool
}

func New(upstream string, opts Options) (DNSClient, error) {
	logger.Debug("Creating DNS client for upstream: %s with options: %+v", upstream, opts)

	parsedURL, err := url.Parse(upstream)
	if err != nil {
		logger.Error("Invalid upstream format: %v", err)
		return nil, fmt.Errorf("invalid upstream format: %w", err)
	}

	var baseClient DNSClient

	if parsedURL.Scheme != "" {
		logger.Debug("Parsing %s as URL with scheme %s", upstream, parsedURL.Scheme)
		baseClient, err = createClientFromURL(parsedURL, opts)
	} else {
		logger.Debug("Parsing %s as plain DNS address", upstream)
		baseClient, err = createClientFromPlainAddress(upstream, opts)
	}

	if err != nil {
		logger.Error("Failed to create base client: %v", err)
		return nil, err
	}

	// Without DNSSEC, the base protocol client is returned directly.
	if !opts.DNSSEC {
		logger.Debug("DNSSEC disabled, returning base client")
		return baseClient, nil
	}

	// With DNSSEC, wrap the base client with a validating client.
	return NewValidating(baseClient, opts), nil
}

func createClientFromURL(parsedURL *url.URL, opts Options) (DNSClient, error) {
	scheme := strings.ToLower(parsedURL.Scheme)
	host := parsedURL.Hostname()
	if host == "" {
		logger.Error("Missing host in upstream URL: %s", parsedURL.String())
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

	logger.Debug("Creating client from URL: scheme=%s, host=%s, port=%s, path=%s", scheme, host, port, path)
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
		logger.Error("Empty host in address: %s", address)
		return nil, fmt.Errorf("empty host in address: %s", address)
	}

	logger.Debug("Creating client from plain address: host=%s, port=%s", host, port)
	return createClient("udp", host, port, "", opts)
}

func getDefaultPort(scheme string) string {
	port := "53"
	switch scheme {
	case "https", "doh", "doh3":
		port = "443"
	case "tls", "dot":
		port = "853"
	case "quic", "doq":
		port = "853"
	case "dnscrypt":
		port = "443"
	}
	logger.Debug("Default port for scheme %s: %s", scheme, port)
	return port
}

func getDefaultPath(scheme string) string {
	path := ""
	switch scheme {
	case "https", "doh", "doh3":
		path = "/dns-query"
	}
	logger.Debug("Default path for scheme %s: %s", scheme, path)
	return path
}

func createClient(scheme, host, port, path string, opts Options) (DNSClient, error) {
	logger.Debug("Creating client: scheme=%s, host=%s, port=%s, path=%s, DNSSEC=%v, KeepAlive=%v",
		scheme, host, port, path, opts.DNSSEC, opts.KeepAlive)

	switch scheme {
	case "udp", "doudp", "":
		config := doudp.Config{
			HostAndPort: net.JoinHostPort(host, port),
			DNSSEC:      opts.DNSSEC,
		}
		logger.Debug("Creating DoUDP client with config: %+v", config)
		return doudp.New(config)

	case "tcp", "dotcp":
		config := dotcp.Config{
			HostAndPort: net.JoinHostPort(host, port),
			DNSSEC:      opts.DNSSEC,
			KeepAlive:   opts.KeepAlive,
		}
		logger.Debug("Creating DoTCP client with config: %+v", config)
		return dotcp.New(config)

	case "https", "doh":
		config := doh.Config{
			Host:      host,
			Port:      port,
			Path:      path,
			DNSSEC:    opts.DNSSEC,
			HTTP3:     false,
			KeepAlive: opts.KeepAlive,
		}
		logger.Debug("Creating DoH client with config: %+v", config)
		return doh.New(config)

	case "doh3":
		config := doh.Config{
			Host:      host,
			Port:      port,
			Path:      path,
			DNSSEC:    opts.DNSSEC,
			HTTP3:     true,
			KeepAlive: opts.KeepAlive,
		}
		logger.Debug("Creating DoH3 client with config: %+v", config)
		return doh.New(config)

	case "tls", "dot":
		config := dot.Config{
			Host:      host,
			Port:      port,
			DNSSEC:    opts.DNSSEC,
			KeepAlive: opts.KeepAlive,
		}
		logger.Debug("Creating DoT client with config: %+v", config)
		return dot.New(config)

	case "sdns":
		config := dnscrypt.Config{
			ServerStamp: fmt.Sprintf("%v://%v", scheme, host),
			DNSSEC:      opts.DNSSEC,
		}
		logger.Debug("Creating DNSCrypt client with stamp")
		return dnscrypt.New(config)

	case "doq":
		config := doq.Config{
			Host:   host,
			Port:   port,
			DNSSEC: opts.DNSSEC,
		}
		logger.Debug("Creating DoQ client with config: %+v", config)
		return doq.New(config)

	default:
		logger.Error("Unsupported scheme: %s", scheme)
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}
}
