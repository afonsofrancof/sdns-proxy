package dot

import (
	"crypto/tls"
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
	Host         string
	Port         string
	DNSSEC       bool
	KeepAlive    bool
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	Debug        bool
}

type Client struct {
	hostAndPort string
	tlsConfig   *tls.Config
	config      Config
	conn        *tls.Conn
	connMutex   sync.Mutex
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DoT client: %s:%s (KeepAlive: %v)", config.Host, config.Port, config.KeepAlive)
	
	if config.Host == "" {
		logger.Error("DoT client creation failed: empty host")
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

	client := &Client{
		hostAndPort: hostAndPort,
		tlsConfig:   tlsConfig,
		config:      config,
	}

	// If keep-alive is enabled, establish connection now
	if config.KeepAlive {
		if err := client.ensureConnection(); err != nil {
			logger.Error("DoT failed to establish initial connection: %v", err)
			return nil, fmt.Errorf("failed to establish initial connection: %w", err)
		}
	}

	logger.Debug("DoT client created: %s (DNSSEC: %v, KeepAlive: %v)", hostAndPort, config.DNSSEC, config.KeepAlive)
	return client, nil
}

func (c *Client) Close() {
	logger.Debug("Closing DoT client")
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

	// Check if existing connection is still valid
	if c.conn != nil {
		// Test the connection with a very short deadline
		if err := c.conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err == nil {
			// Try to read one byte to test connection
			var testBuf [1]byte
			_, err := c.conn.Read(testBuf[:])
			
			// Reset deadline
			c.conn.SetReadDeadline(time.Time{})
			
			// If we get a timeout error, connection is still good
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil
			}
			
			// Any other error means connection is dead
			logger.Debug("DoT connection test failed, reconnecting: %v", err)
			c.conn.Close()
			c.conn = nil
		}
	}

	logger.Debug("Establishing DoT connection to %s", c.hostAndPort)
	dialer := &net.Dialer{
		Timeout: c.config.WriteTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", c.hostAndPort, c.tlsConfig)
	if err != nil {
		logger.Error("DoT connection failed to %s: %v", c.hostAndPort, err)
		return err
	}
	
	c.conn = conn
	logger.Debug("DoT connection established to %s", c.hostAndPort)
	return nil
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("DoT query: %s %s to %s", question.Name, dns.TypeToString[question.Qtype], c.hostAndPort)
	}

	// Ensure we have a connection (either persistent or new)
	if c.config.KeepAlive {
		if err := c.ensureConnection(); err != nil {
			return nil, fmt.Errorf("dot: failed to ensure connection: %w", err)
		}
	} else {
		// For non-keepalive mode, create a fresh connection for each query
		c.connMutex.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.connMutex.Unlock()
		
		if err := c.ensureConnection(); err != nil {
			return nil, fmt.Errorf("dot: failed to create connection: %w", err)
		}
	}

	// Prepare DNS message
	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}
	packed, err := msg.Pack()
	if err != nil {
		logger.Error("DoT failed to pack message: %v", err)
		return nil, fmt.Errorf("dot: failed to pack message: %w", err)
	}

	// Prepend message length (DNS over TCP format)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(packed)))
	data := append(length, packed...)

	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()

	// Write query
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
		logger.Error("DoT failed to set write deadline: %v", err)
		return nil, fmt.Errorf("dot: failed to set write deadline: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		logger.Error("DoT failed to write message to %s: %v", c.hostAndPort, err)
		
		// If keep-alive is enabled and write failed, try to reconnect once
		if c.config.KeepAlive {
			logger.Debug("DoT write failed with keep-alive, attempting reconnect")
			if reconnectErr := c.ensureConnection(); reconnectErr != nil {
				return nil, fmt.Errorf("dot: failed to reconnect: %w", reconnectErr)
			}
			
			c.connMutex.Lock()
			conn = c.conn
			c.connMutex.Unlock()
			
			if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
				return nil, fmt.Errorf("dot: failed to set write deadline after reconnect: %w", err)
			}
			
			if _, err := conn.Write(data); err != nil {
				return nil, fmt.Errorf("dot: failed to write message after reconnect: %w", err)
			}
		} else {
			return nil, fmt.Errorf("dot: failed to write message: %w", err)
		}
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
		logger.Error("DoT failed to set read deadline: %v", err)
		return nil, fmt.Errorf("dot: failed to set read deadline: %w", err)
	}

	// Read message length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		logger.Error("DoT failed to read response length from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("dot: failed to read response length: %w", err)
	}

	msgLen := binary.BigEndian.Uint16(lengthBuf)
	if msgLen > dns.MaxMsgSize {
		logger.Error("DoT response too large from %s: %d bytes", c.hostAndPort, msgLen)
		return nil, fmt.Errorf("dot: response message too large: %d", msgLen)
	}

	// Read message body
	buffer := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		logger.Error("DoT failed to read response from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("dot: failed to read response: %w", err)
	}

	// Parse response
	response := new(dns.Msg)
	if err := response.Unpack(buffer); err != nil {
		logger.Error("DoT failed to unpack response from %s: %v", c.hostAndPort, err)
		return nil, fmt.Errorf("dot: failed to unpack response: %w", err)
	}

	if len(response.Answer) > 0 {
		logger.Debug("DoT response from %s: %d answers", c.hostAndPort, len(response.Answer))
	}

	// Close the connection if not using keep-alive
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
