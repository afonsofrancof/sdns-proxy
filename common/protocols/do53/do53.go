package do53

import (
	"fmt"
	"net"
	"time"

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
	if config.HostAndPort == "" {
		return nil, fmt.Errorf("do53: HostAndPort cannot be empty")
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 2 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 5 * time.Second
	}

	return &Client{
		hostAndPort: config.HostAndPort,
		config:      config,
	}, nil
}

func (c *Client) Close() {
}

func (c *Client) createConnection() (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", c.hostAndPort)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	return net.DialUDP("udp", nil, udpAddr)
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	// Create connection for this query
	conn, err := c.createConnection()
	if err != nil {
		return nil, fmt.Errorf("do53: failed to create connection: %w", err)
	}
	defer conn.Close()

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}

	packedMsg, err := msg.Pack()

	if err != nil {
		return nil, fmt.Errorf("do53: failed to pack DNS message: %w", err)
	}

	// Send query
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
		return nil, fmt.Errorf("do53: failed to set write deadline: %w", err)
	}

	if _, err := conn.Write(packedMsg); err != nil {
		return nil, fmt.Errorf("do53: failed to send DNS query: %w", err)
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("do53: failed to set read deadline: %w", err)
	}

	buffer := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("do53: failed to read DNS response: %w", err)
	}

	// Parse response
	response := new(dns.Msg)
	if err := response.Unpack(buffer[:n]); err != nil {
		return nil, fmt.Errorf("do53: failed to unpack DNS response: %w", err)
	}

	return response, nil
}
