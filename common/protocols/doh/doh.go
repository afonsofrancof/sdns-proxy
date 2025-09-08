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
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const dnsMessageContentType = "application/dns-message"

type Config struct {
	Host   string
	Port   string
	Path   string
	DNSSEC bool
	HTTP3  bool
	HTTP2  bool
}

type Client struct {
	httpClient  *http.Client
	upstreamURL *url.URL
	config      Config
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DoH client: %s:%s%s", config.Host, config.Port, config.Path)
	
	if config.Host == "" || config.Port == "" || config.Path == "" {
		logger.Error("DoH client creation failed: missing required fields")
		return nil, errors.New("doh: host, port, and path must not be empty")
	}

	if !strings.HasPrefix(config.Path, "/") {
		config.Path = "/" + config.Path
	}
	rawURL := "https://" + net.JoinHostPort(config.Host, config.Port) + config.Path

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		logger.Error("Failed to parse DoH URL %s: %v", rawURL, err)
		return nil, fmt.Errorf("doh: failed to parse constructed URL %q: %w", rawURL, err)
	}

	tlsConfig := &tls.Config{
		ServerName:         config.Host,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:          30 * time.Second,
		DisablePathMTUDiscovery: true,
	}

	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = tlsConfig
	httpClient := &http.Client{
		Transport: transport,
	}

	var transportType string
	if config.HTTP2 {
		httpClient.Transport = &http2.Transport{
			TLSClientConfig: tlsConfig,
			AllowHTTP:       true,
		}
		transportType = "HTTP/2"
	} else if config.HTTP3 {
		quicTlsConfig := http3.ConfigureTLSConfig(tlsConfig)
		httpClient.Transport = &http3.Transport{
			TLSClientConfig: quicTlsConfig,
			QUICConfig:      quicConfig,
		}
		transportType = "HTTP/3"
	} else {
		transportType = "HTTP/1.1"
	}

	logger.Debug("DoH client created: %s (%s, DNSSEC: %v)", rawURL, transportType, config.DNSSEC)

	return &Client{
		httpClient:  httpClient,
		upstreamURL: parsedURL,
		config:      config,
	}, nil
}

func (c *Client) Close() {
	logger.Debug("Closing DoH client")
	if t, ok := c.httpClient.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	} else if t3, ok := c.httpClient.Transport.(*http3.Transport); ok {
		t3.CloseIdleConnections()
	}
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("DoH query: %s %s to %s", question.Name, dns.TypeToString[question.Qtype], c.upstreamURL.Host)
	}

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}
	
	packedMsg, err := msg.Pack()
	if err != nil {
		logger.Error("DoH failed to pack DNS message: %v", err)
		return nil, fmt.Errorf("doh: failed to pack DNS message: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.upstreamURL.String(), bytes.NewReader(packedMsg))
	if err != nil {
		logger.Error("DoH failed to create HTTP request: %v", err)
		return nil, fmt.Errorf("doh: failed to create HTTP request object: %w", err)
	}

	httpReq.Header.Set("User-Agent", "sdns-proxy")
	httpReq.Header.Set("Content-Type", dnsMessageContentType)
	httpReq.Header.Set("Accept", dnsMessageContentType)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Error("DoH request failed to %s: %v", c.upstreamURL.Host, err)
		return nil, fmt.Errorf("doh: failed executing HTTP request to %s: %w", c.upstreamURL.Host, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		logger.Error("DoH received non-200 status from %s: %s", c.upstreamURL.Host, httpResp.Status)
		return nil, fmt.Errorf("doh: received non-200 HTTP status from %s: %s", c.upstreamURL.Host, httpResp.Status)
	}

	if ct := httpResp.Header.Get("Content-Type"); ct != dnsMessageContentType {
		logger.Error("DoH unexpected Content-Type from %s: %s", c.upstreamURL.Host, ct)
		return nil, fmt.Errorf("doh: unexpected Content-Type from %s: got %q, want %q", c.upstreamURL.Host, ct, dnsMessageContentType)
	}

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logger.Error("DoH failed reading response from %s: %v", c.upstreamURL.Host, err)
		return nil, fmt.Errorf("doh: failed reading response body from %s: %w", c.upstreamURL.Host, err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBody)
	if err != nil {
		logger.Error("DoH failed to unpack response from %s: %v", c.upstreamURL.Host, err)
		return nil, fmt.Errorf("doh: failed to unpack DNS response from %s: %w", c.upstreamURL.Host, err)
	}

	if len(recvMsg.Answer) > 0 {
		logger.Debug("DoH response from %s: %d answers", c.upstreamURL.Host, len(recvMsg.Answer))
	}

	return recvMsg, nil
}
