package dotcp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

type Config struct {
	HostAndPort  string
	DNSSEC       bool
	KeepAlive    bool
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
}

type Client struct {
	hostAndPort string
	config      Config
	conn        net.Conn
	connMutex   sync.Mutex
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DoTCP client: %s (KeepAlive: %v)", config.HostAndPort, config.KeepAlive)

	if config.HostAndPort == "" {
		logger.Error("DoTCP client creation failed: empty HostAndPort")
		return nil, fmt.Errorf("dotcp: HostAndPort cannot be empty")
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 2 * time.Second
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 5 * time.Second
	}

	client := &Client{
		hostAndPort: config.HostAndPort,
		config:      config,
	}

	if config.KeepAlive {
		if err := client.ensureConnection(); err != nil {
			logger.Error("DoTCP failed to establish initial connection: %v", err)
			return nil, fmt.Errorf("failed to establish initial connection: %w", err)
		}
	}

	logger.Debug("DoTCP client created: %s (DNSSEC: %v, KeepAlive: %v)", config.HostAndPort, config.DNSSEC, config.KeepAlive)
	return client, nil
}

func (c *Client) Close() {
	logger.Debug("Closing DoTCP client")
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) ensureConnection() error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if c.conn != nil {
		if err := c.conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err == nil {
			var testBuf [1]byte
			_, err := c.conn.Read(testBuf[:])
			c.conn.SetReadDeadline(time.Time{})

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil
			}

			logger.Debug("DoTCP connection test failed, reconnecting: %v", err)
			c.conn.Close()
			c.conn = nil
		}
	}

	logger.Debug("Establishing DoTCP connection to %s", c.hostAndPort)
	dialer := &net.Dialer{
		Timeout: c.config.WriteTimeout,
	}

	conn, err := dialer.Dial("tcp", c.hostAndPort)
	if err != nil {
		logger.Error("DoTCP connection failed to %s: %v", c.hostAndPort, err)
		return err
	}

	c.conn = conn
	logger.Debug("DoTCP connection established to %s", c.hostAndPort)
	return nil
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("DoTCP query: %s %s to %s", question.Name, dns.TypeToString[question.Qtype], c.hostAndPort)
	}

	if c.config.KeepAlive {
		if err := c.ensureConnection(); err != nil {
			return nil, fmt.Errorf("dotcp: failed to ensure connection: %w", err)
		}
	} else {
		c.connMutex.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.connMutex.Unlock()

		if err := c.ensureConnection(); err != nil {
			return nil, fmt.Errorf("dotcp: failed to create connection: %w", err)
		}
	}

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}

	packed, err := msg.Pack()
	if err != nil {
		logger.Error("DoTCP failed to pack message: %v", err)
		return nil, fmt.Errorf("dotcp: failed to pack message: %w", err)
	}

	// DNS over TCP uses 2-byte length prefix
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(packed)))
	data := append(length, packed...)

	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()

	if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
		logger.Error("DoTCP failed to set write deadline: %v", err)
		return nil, fmt.Errorf("dotcp: failed to set write deadline: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		logger.Error("DoTCP failed to write message to %s: %v", c.hostAndPort, err)

		if c.config.KeepAlive {
			logger.Debug("DoTCP write failed with keep-alive, attempting reconnect")
			if reconnectErr := c.ensureConnection(); reconnectErr != nil {
				return nil, fmt.Errorf("dotcp: failed to reconnect: %w", reconnectErr)
			}

			c.connMutex.Lock()
			conn = c.conn
			c.connMutex.Unlock()

			if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
				return nil, fmt.Errorf("dotcp: failed to set write deadline after reconnect: %w", err)
			}

			if _, err := conn.Write(data); err != nil {
				return nil, fmt.Errorf("dotcp: failed to write message after reconnect: %w", err)
			}
		} else {
			return nil, fmt.Errorf("dotcp: failed to write message: %w", err)
		}
	}

	if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
		logger.Error("DoTCP failed to set read deadline: %v", err)
		return nil, fmt.Errorf("dotcp: failed to set read deadline: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		logger.Error("DoTCP failed to read response length from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("dotcp: failed to read response length: %w", err)
	}

	msgLen := binary.BigEndian.Uint16(lengthBuf)
	if msgLen > dns.MaxMsgSize {
		logger.Error("DoTCP response too large from %s: %d bytes", c.hostAndPort, msgLen)
		return nil, fmt.Errorf("dotcp: response message too large: %d", msgLen)
	}

	buffer := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		logger.Error("DoTCP failed to read response from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("dotcp: failed to read response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(buffer); err != nil {
		logger.Error("DoTCP failed to unpack response from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("dotcp: failed to unpack response: %w", err)
	}

	if len(response.Answer) > 0 {
		logger.Debug("DoTCP response from %s: %d answers", c.hostAndPort, len(response.Answer))
	}

	if !c.config.KeepAlive {
		c.connMutex.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.connMutex.Unlock()
	}

	return response, nil
}
