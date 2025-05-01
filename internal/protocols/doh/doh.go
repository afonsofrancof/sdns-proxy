package doh

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

const dnsMessageContentType = "application/dns-message"

type Config struct {
	Host   string
	Port   string
	Path   string
	DNSSEC bool
}

type Client struct {
	httpClient  *http.Client
	upstreamURL *url.URL
	config      Config
}

func New(config Config) (*Client, error) {
	if config.Host == "" || config.Port == "" || config.Path == "" {
		fmt.Printf("%v,%v,%v", config.Host,config.Port,config.Path)
		return nil, errors.New("doh: host, port, and path must not be empty")
	}

	if !strings.HasPrefix(config.Path, "/") {
		config.Path = "/" + config.Path
	}
	rawURL := "https://" + net.JoinHostPort(config.Host, config.Port) + config.Path

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("doh: failed to parse constructed URL %q: %w", rawURL, err)
	}

	tlsConfig := &tls.Config{
		ServerName: config.Host,
		MinVersion: tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	return &Client{
		httpClient:  httpClient,
		upstreamURL: parsedURL,
		config:      config,
	}, nil
}

// Close cleans up idle connections held by the underlying HTTP transport.
func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}

func (c *Client) Query(domain string, queryType uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)
	msg.Id = dns.Id()
	msg.RecursionDesired = true

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}

	packedMsg, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: failed to pack DNS message: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.upstreamURL.String(), bytes.NewReader(packedMsg))
	if err != nil {
		return nil, fmt.Errorf("doh: failed to create HTTP request object: %w", err)
	}

	httpReq.Header.Set("User-Agent", "sdns-perf")
	httpReq.Header.Set("Content-Type", dnsMessageContentType)
	httpReq.Header.Set("Accept", dnsMessageContentType)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh: failed executing HTTP request to %s: %w", c.upstreamURL.Host, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: received non-200 HTTP status from %s: %s", c.upstreamURL.Host, httpResp.Status)
	}

	if ct := httpResp.Header.Get("Content-Type"); ct != dnsMessageContentType {
		return nil, fmt.Errorf("doh: unexpected Content-Type from %s: got %q, want %q", c.upstreamURL.Host, ct, dnsMessageContentType)
	}

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh: failed reading response body from %s: %w", c.upstreamURL.Host, err)
	}

	// Unpack the DNS message
	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBody)
	if err != nil {
		return nil, fmt.Errorf("doh: failed to unpack DNS response from %s: %w", c.upstreamURL.Host, err)
	}

	return recvMsg, nil
}
