package doudp

import (
	"fmt"
	"net"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

type Config struct {
	HostAndPort  string
	DNSSEC       bool
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
}

type Client struct {
	hostAndPort string
	config      Config
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DoUDP client: %s", config.HostAndPort)

	if config.HostAndPort == "" {
		logger.Error("DoUDP client creation failed: empty HostAndPort")
		return nil, fmt.Errorf("doudp: HostAndPort cannot be empty")
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 2 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 5 * time.Second
	}

	logger.Debug("DoUDP client created: %s (DNSSEC: %v)", config.HostAndPort, config.DNSSEC)

	return &Client{
		hostAndPort: config.HostAndPort,
		config:      config,
	}, nil
}

func (c *Client) Close() {
	logger.Debug("Closing DoUDP client")
}

func (c *Client) createConnection() (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", c.hostAndPort)
	if err != nil {
		logger.Error("DoUDP failed to resolve address %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Error("DoUDP failed to connect to %s: %v", c.hostAndPort, err)
		return nil, err
	}

	logger.Debug("DoUDP connection established to %s", c.hostAndPort)
	return conn, nil
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("DoUDP query: %s %s to %s", question.Name, dns.TypeToString[question.Qtype], c.hostAndPort)
	}

	conn, err := c.createConnection()
	if err != nil {
		return nil, fmt.Errorf("doudp: failed to create connection: %w", err)
	}
	defer conn.Close()

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}

	packedMsg, err := msg.Pack()
	if err != nil {
		logger.Error("DoUDP failed to pack message: %v", err)
		return nil, fmt.Errorf("doudp: failed to pack DNS message: %w", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
		logger.Error("DoUDP failed to set write deadline: %v", err)
		return nil, fmt.Errorf("doudp: failed to set write deadline: %w", err)
	}

	if _, err := conn.Write(packedMsg); err != nil {
		logger.Error("DoUDP failed to send query to %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("doudp: failed to send DNS query: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
		logger.Error("DoUDP failed to set read deadline: %v", err)
		return nil, fmt.Errorf("doudp: failed to set read deadline: %w", err)
	}

	buffer := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buffer)
	if err != nil {
		logger.Error("DoUDP failed to read response from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("doudp: failed to read DNS response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(buffer[:n]); err != nil {
		logger.Error("DoUDP failed to unpack response from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("doudp: failed to unpack DNS response: %w", err)
	}

	if len(response.Answer) > 0 {
		logger.Debug("DoUDP response from %s: %d answers", c.hostAndPort, len(response.Answer))
	}

	return response, nil
}
