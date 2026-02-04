package dnscrypt

import (
	"fmt"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

type Config struct {
	ServerStamp  string
	DNSSEC       bool
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
}

type Client struct {
	resolver *dnscrypt.Client
	config   Config
	ri       *dnscrypt.ResolverInfo
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DNSCrypt client with stamp: %s", config.ServerStamp)

	if config.ServerStamp == "" {
		logger.Error("DNSCrypt client creation failed: empty ServerStamp")
		return nil, fmt.Errorf("dnscrypt: ServerStamp cannot be empty")
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 5 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 10 * time.Second
	}

	resolver := &dnscrypt.Client{
		Net:     "udp",
		Timeout: config.ReadTimeout,
	}

	// Resolve the server info from the stamp
	ri, err := resolver.Dial(config.ServerStamp)
	if err != nil {
		logger.Error("DNSCrypt failed to dial server: %v", err)
		return nil, fmt.Errorf("dnscrypt: failed to dial server: %w", err)
	}

	logger.Debug("DNSCrypt client created (DNSSEC: %v)", config.DNSSEC)

	return &Client{
		resolver: resolver,
		config:   config,
		ri:       ri,
	}, nil
}

func (c *Client) Close() {
	// The dnscrypt library doesn't require explicit cleanup
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("DNSCrypt query: %s %s", question.Name, dns.TypeToString[question.Qtype])
	}

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}

	response, err := c.resolver.Exchange(msg, c.ri)
	if err != nil {
		logger.Error("DNSCrypt query failed: %v", err)
		return nil, fmt.Errorf("dnscrypt: query failed: %w", err)
	}

	if len(response.Answer) > 0 {
		logger.Debug("DNSCrypt response: %d answers", len(response.Answer))
	}

	return response, nil
}
