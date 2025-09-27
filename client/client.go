package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/afonsofrancof/sdns-proxy/common/dnssec"
	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/do53"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/doh"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/doq"
	"github.com/afonsofrancof/sdns-proxy/common/protocols/dot"
	"github.com/miekg/dns"
)

type DNSClient interface {
	Query(msg *dns.Msg) (*dns.Msg, error)
	Close()
}

type ValidatingDNSClient struct {
	client    DNSClient
	validator *dnssec.Validator
	options   Options
}

type Options struct {
	DNSSEC           bool
	ValidateOnly     bool
	StrictValidation bool
	KeepAlive        bool // New flag for long-lived connections
}

// New creates a DNS client based on the upstream string
func New(upstream string, opts Options) (DNSClient, error) {
	logger.Debug("Creating DNS client for upstream: %s with options: %+v", upstream, opts)

	// Try to parse as URL first
	parsedURL, err := url.Parse(upstream)
	if err != nil {
		logger.Error("Invalid upstream format: %v", err)
		return nil, fmt.Errorf("invalid upstream format: %w", err)
	}

	var baseClient DNSClient

	// If it has a scheme, treat it as a full URL
	if parsedURL.Scheme != "" {
		logger.Debug("Parsing %s as URL with scheme %s", upstream, parsedURL.Scheme)
		baseClient, err = createClientFromURL(parsedURL, opts)
	} else {
		// No scheme - treat as plain DNS address
		logger.Debug("Parsing %s as plain DNS address", upstream)
		baseClient, err = createClientFromPlainAddress(upstream, opts)
	}

	if err != nil {
		logger.Error("Failed to create base client: %v", err)
		return nil, err
	}

	// If DNSSEC is not enabled, return the base client
	if !opts.DNSSEC {
		logger.Debug("DNSSEC disabled, returning base client")
		return baseClient, nil
	}

	logger.Debug("DNSSEC enabled, wrapping with validator")
	validator := dnssec.NewValidatorWithAuthoritativeQueries()

	return &ValidatingDNSClient{
		client:    baseClient,
		validator: validator,
		options:   opts,
	}, nil
}

func (v *ValidatingDNSClient) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("ValidatingDNSClient query: %s %s (DNSSEC: %v, ValidateOnly: %v, StrictValidation: %v)",
			question.Name, dns.TypeToString[question.Qtype], v.options.DNSSEC, v.options.ValidateOnly, v.options.StrictValidation)
	}

	// Always query the upstream first
	response, err := v.client.Query(msg)
	if err != nil {
		logger.Debug("Base client query failed: %v", err)
		return nil, err
	}

	// If DNSSEC validation is disabled, return response as-is
	if !v.options.DNSSEC {
		return response, nil
	}

	// Extract question details for validation
	if len(msg.Question) == 0 {
		logger.Debug("No questions in message, skipping DNSSEC validation")
		return response, nil
	}

	question := msg.Question[0]
	qname := question.Name
	qtype := question.Qtype

	logger.Debug("Starting DNSSEC validation for %s %s", qname, dns.TypeToString[qtype])

	// Validate the response
	validationErr := v.validator.ValidateResponse(response, qname, qtype)

	// Handle validation results based on options
	if validationErr != nil {
		// Check if it's a "not signed" error
		if validationErr == dnssec.ErrResourceNotSigned {
			logger.Debug("Domain %s is not DNSSEC signed", qname)
			if v.options.ValidateOnly {
				logger.Error("Domain %s is not DNSSEC signed (ValidateOnly mode)", qname)
				return nil, fmt.Errorf("domain %s is not DNSSEC signed", qname)
			}
			// Return unsigned response if not in validate-only mode
			logger.Debug("Returning unsigned response for %s", qname)
			return response, nil
		}

		// For other validation errors
		logger.Debug("DNSSEC validation failed for %s: %v", qname, validationErr)
		if v.options.StrictValidation {
			logger.Error("DNSSEC validation failed for %s (strict mode): %v", qname, validationErr)
			return nil, fmt.Errorf("DNSSEC validation failed for %s: %w", qname, validationErr)
		}

		// In non-strict mode, log the error but return the response
		logger.Debug("DNSSEC validation failed for %s (non-strict mode), returning response anyway: %v", qname, validationErr)
		return response, nil
	}

	// Validation successful
	logger.Debug("DNSSEC validation successful for %s %s", qname, dns.TypeToString[qtype])
	return response, nil
}

func (v *ValidatingDNSClient) Close() {
	logger.Debug("Closing ValidatingDNSClient")
	if v.client != nil {
		v.client.Close()
	}
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
	return createClient("", host, port, "", opts)
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
	case "udp", "tcp", "do53", "":
		config := do53.Config{
			HostAndPort: net.JoinHostPort(host, port),
			DNSSEC:      opts.DNSSEC,
		}
		logger.Debug("Creating DO53 client with config: %+v", config)
		return do53.New(config)

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

	case "doq": // DNS over QUIC
		config := doq.Config{
			Host:      host,
			Port:      port,
			DNSSEC:    opts.DNSSEC,
			KeepAlive: opts.KeepAlive,
		}
		logger.Debug("Creating DoQ client with config: %+v", config)
		return doq.New(config)

	default:
		logger.Error("Unsupported scheme: %s", scheme)
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}
}
