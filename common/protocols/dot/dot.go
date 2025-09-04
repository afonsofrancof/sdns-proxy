package dot

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	Host         string
	Port         string
	DNSSEC       bool
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	Debug        bool
}

type Client struct {
	hostAndPort string
	tlsConfig   *tls.Config
	config      Config
}

func New(config Config) (*Client, error) {
	if config.Host == "" {
		return nil, fmt.Errorf("dot: Host cannot be empty")
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 2 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 5 * time.Second
	}

	hostAndPort := net.JoinHostPort(config.Host, config.Port)

	tlsConfig := &tls.Config{
		ServerName: config.Host,
	}

	return &Client{
		hostAndPort: hostAndPort,
		tlsConfig:   tlsConfig,
		config:      config,
	}, nil
}

func (c *Client) Close() {
}

func (c *Client) createConnection() (*tls.Conn, error) {
	dialer := &net.Dialer{
		Timeout: c.config.WriteTimeout,
	}

	return tls.DialWithDialer(dialer, "tcp", c.hostAndPort, c.tlsConfig)
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	// Create connection for this query
	conn, err := c.createConnection()
	if err != nil {
		return nil, fmt.Errorf("dot: failed to create connection: %w", err)
	}
	defer conn.Close()

	// Prepare DNS message
	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("dot: failed to pack message: %w", err)
	}

	// Prepend message length (DNS over TCP format)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(packed)))
	data := append(length, packed...)

	// Write query
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
		return nil, fmt.Errorf("dot: failed to set write deadline: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("dot: failed to write message: %w", err)
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("dot: failed to set read deadline: %w", err)
	}

	// Read message length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("dot: failed to read response length: %w", err)
	}

	msgLen := binary.BigEndian.Uint16(lengthBuf)
	if msgLen > dns.MaxMsgSize {
		return nil, fmt.Errorf("dot: response message too large: %d", msgLen)
	}

	// Read message body
	buffer := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return nil, fmt.Errorf("dot: failed to read response: %w", err)
	}

	// Parse response
	response := new(dns.Msg)
	if err := response.Unpack(buffer); err != nil {
		return nil, fmt.Errorf("dot: failed to unpack response: %w", err)
	}

	return response, nil
}
