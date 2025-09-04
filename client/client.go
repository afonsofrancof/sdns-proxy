package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/afonsofrancof/sdns-proxy/common/dnssec"
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
	DNSSEC         bool
	ValidateOnly   bool
	StrictValidation bool
}

// New creates a DNS client based on the upstream string
func New(upstream string, opts Options) (DNSClient, error) {
	// Try to parse as URL first
	parsedURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream format: %w", err)
	}

	var baseClient DNSClient

	// If it has a scheme, treat it as a full URL
	if parsedURL.Scheme != "" {
		baseClient, err = createClientFromURL(parsedURL, opts)
	} else {
		// No scheme - treat as plain DNS address
		baseClient, err = createClientFromPlainAddress(upstream, opts)
	}

	if err != nil {
		return nil, err
	}

	// If DNSSEC is not enabled, return the base client
	if !opts.DNSSEC {
		return baseClient, nil
	}

	// Wrap with DNSSEC validation
	// validator := dnssec.NewValidator(func(qname string, qtype uint16) (*dns.Msg, error) {
	// 	msg := new(dns.Msg)
	// 	msg.SetQuestion(dns.Fqdn(qname), qtype)
	// 	msg.Id = dns.Id()
	// 	msg.RecursionDesired = true
	// 	msg.SetEdns0(4096, true) // Enable DNSSEC
	// 	return baseClient.Query(msg)
	// })
	validator := dnssec.NewValidatorWithAuthoritativeQueries()

	return &ValidatingDNSClient{
		client:    baseClient,
		validator: validator,
		options:   opts,
	}, nil
}

func (v *ValidatingDNSClient) Query(msg *dns.Msg) (*dns.Msg, error) {
	// Always query the upstream first
	response, err := v.client.Query(msg)
	if err != nil {
		return nil, err
	}

	// If DNSSEC validation is disabled, return response as-is
	if !v.options.DNSSEC {
		return response, nil
	}

	// Extract question details for validation
	if len(msg.Question) == 0 {
		return response, nil
	}

	question := msg.Question[0]
	qname := question.Name
	qtype := question.Qtype

	// Validate the response
	validationErr := v.validator.ValidateResponse(response, qname, qtype)

	// Handle validation results based on options
	if validationErr != nil {
		// Check if it's a "not signed" error
		if validationErr == dnssec.ErrResourceNotSigned {
			if v.options.ValidateOnly {
				return nil, fmt.Errorf("domain %s is not DNSSEC signed", qname)
			}
			// Return unsigned response if not in validate-only mode
			return response, nil
		}

		// For other validation errors
		if v.options.StrictValidation {
			return nil, fmt.Errorf("DNSSEC validation failed for %s: %w", qname, validationErr)
		}

		// In non-strict mode, log the error but return the response
		// (You might want to add logging here)
		return response, nil
	}

	// Validation successful
	return response, nil
}

func (v *ValidatingDNSClient) Close() {
	if v.client != nil {
		v.client.Close()
	}
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
