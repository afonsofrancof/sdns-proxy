package doq

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type Config struct {
	Host      string
	Port      string
	Debug     bool
	DNSSEC    bool
	KeepAlive bool
}

type Client struct {
	targetAddr    *net.UDPAddr
	tlsConfig     *tls.Config
	udpConn       *net.UDPConn
	quicConn      quic.Connection
	quicTransport *quic.Transport
	quicConfig    *quic.Config
	config        Config
	connMutex     sync.Mutex
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DoQ client: %s:%s (KeepAlive: %v)", config.Host, config.Port, config.KeepAlive)

	tlsConfig := &tls.Config{
		ServerName:         config.Host,
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
		NextProtos:         []string{"doq"},
	}

	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Host, config.Port))
	if err != nil {
		logger.Error("DoQ failed to resolve address %s:%s: %v", config.Host, config.Port, err)
		return nil, err
	}
	
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		logger.Error("DoQ failed to create UDP connection: %v", err)
		return nil, fmt.Errorf("failed to connect to target address: %w", err)
	}

	quicTransport := quic.Transport{
		Conn: udpConn,
	}

	quicConfig := quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

	client := &Client{
		targetAddr:    targetAddr,
		tlsConfig:     tlsConfig,
		udpConn:       udpConn,
		quicConn:      nil,
		quicTransport: &quicTransport,
		quicConfig:    &quicConfig,
		config:        config,
	}

	// If keep-alive is enabled, establish connection now
	if config.KeepAlive {
		if err := client.ensureConnection(); err != nil {
			logger.Error("DoQ failed to establish initial connection: %v", err)
			client.Close()
			return nil, fmt.Errorf("failed to establish initial connection: %w", err)
		}
	}

	logger.Debug("DoQ client created: %s:%s (DNSSEC: %v, KeepAlive: %v)", config.Host, config.Port, config.DNSSEC, config.KeepAlive)
	return client, nil
}

func (c *Client) Close() {
	logger.Debug("Closing DoQ client")
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	
	if c.quicConn != nil {
		c.quicConn.CloseWithError(0, "client shutdown")
		c.quicConn = nil
	}
	if c.udpConn != nil {
		c.udpConn.Close()
	}
}

func (c *Client) ensureConnection() error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	// Check if existing connection is still valid
	if c.quicConn != nil {
		select {
		case <-c.quicConn.Context().Done():
			logger.Debug("DoQ connection closed, reconnecting")
			c.quicConn = nil
		default:
			// Connection is still valid
			return nil
		}
	}

	logger.Debug("Establishing DoQ connection to %s", c.targetAddr)
	quicConn, err := c.quicTransport.DialEarly(context.Background(), c.targetAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		logger.Error("DoQ connection failed to %s: %v", c.targetAddr, err)
		return err
	}

	c.quicConn = quicConn
	logger.Debug("DoQ connection established to %s", c.targetAddr)
	return nil
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("DoQ query: %s %s to %s", question.Name, dns.TypeToString[question.Qtype], c.targetAddr)
	}

	// Ensure we have a connection (either persistent or new)
	if c.config.KeepAlive {
		if err := c.ensureConnection(); err != nil {
			return nil, fmt.Errorf("doq: failed to ensure connection: %w", err)
		}
	} else {
		// For non-keepalive mode, create a fresh connection for each query
		c.connMutex.Lock()
		c.quicConn = nil // Force new connection
		c.connMutex.Unlock()
		
		if err := c.ensureConnection(); err != nil {
			return nil, fmt.Errorf("doq: failed to create connection: %w", err)
		}
	}

	// Prepare DNS message
	msg.Id = 0
	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}
	packed, err := msg.Pack()
	if err != nil {
		logger.Error("DoQ failed to pack message: %v", err)
		return nil, fmt.Errorf("doq: failed to pack message: %w", err)
	}

	// Open a stream for this query
	c.connMutex.Lock()
	quicConn := c.quicConn
	c.connMutex.Unlock()
	
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		logger.Error("DoQ failed to open stream: %v", err)
		
		// If keep-alive is enabled, try to reconnect once
		if c.config.KeepAlive {
			logger.Debug("DoQ stream failed with keep-alive, attempting reconnect")
			if reconnectErr := c.ensureConnection(); reconnectErr != nil {
				return nil, fmt.Errorf("doq: failed to reconnect: %w", reconnectErr)
			}
			
			c.connMutex.Lock()
			quicConn = c.quicConn
			c.connMutex.Unlock()
			
			quicStream, err = quicConn.OpenStream()
			if err != nil {
				logger.Error("DoQ failed to open stream after reconnect: %v", err)
				return nil, fmt.Errorf("doq: failed to open stream after reconnect: %w", err)
			}
		} else {
			return nil, fmt.Errorf("doq: failed to open stream: %w", err)
		}
	}

	var lengthPrefixedMessage bytes.Buffer
	err = binary.Write(&lengthPrefixedMessage, binary.BigEndian, uint16(len(packed)))
	if err != nil {
		logger.Error("DoQ failed to write message length: %v", err)
		return nil, fmt.Errorf("failed to write message length: %w", err)
	}
	_, err = lengthPrefixedMessage.Write(packed)
	if err != nil {
		logger.Error("DoQ failed to write DNS message: %v", err)
		return nil, fmt.Errorf("failed to write DNS message: %w", err)
	}

	_, err = quicStream.Write(lengthPrefixedMessage.Bytes())
	if err != nil {
		logger.Error("DoQ failed to write to stream: %v", err)
		return nil, fmt.Errorf("failed writing to QUIC stream: %w", err)
	}
	quicStream.Close()

	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(quicStream, lengthBuf)
	if err != nil {
		logger.Error("DoQ failed to read response length: %v", err)
		return nil, fmt.Errorf("failed reading response length: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBuf)
	if messageLength == 0 {
		logger.Error("DoQ received zero-length message")
		return nil, fmt.Errorf("received zero-length message")
	}

	responseBuf := make([]byte, messageLength)
	_, err = io.ReadFull(quicStream, responseBuf)
	if err != nil {
		logger.Error("DoQ failed to read response data: %v", err)
		return nil, fmt.Errorf("failed reading response data: %w", err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBuf)
	if err != nil {
		logger.Error("DoQ failed to parse response: %v", err)
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	if len(recvMsg.Answer) > 0 {
		logger.Debug("DoQ response from %s: %d answers", c.targetAddr, len(recvMsg.Answer))
	}

	// Close the connection if not using keep-alive
	if !c.config.KeepAlive {
		c.connMutex.Lock()
		if c.quicConn != nil {
			c.quicConn.CloseWithError(0, "query complete")
			c.quicConn = nil
		}
		c.connMutex.Unlock()
	}

	return recvMsg, nil
}
