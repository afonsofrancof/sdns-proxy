package doq

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type Config struct {
	Host   string
	Port   string
	Debug  bool
	DNSSEC bool
}

type Client struct {
	targetAddr    *net.UDPAddr
	tlsConfig     *tls.Config
	udpConn       *net.UDPConn
	quicConn      quic.Connection
	quicTransport *quic.Transport
	quicConfig    *quic.Config
	config        Config
}

func New(config Config) (*Client, error) {
	logger.Debug("Creating DoQ client: %s:%s", config.Host, config.Port)

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

	logger.Debug("DoQ client created: %s:%s (DNSSEC: %v)", config.Host, config.Port, config.DNSSEC)

	return &Client{
		targetAddr:    targetAddr,
		tlsConfig:     tlsConfig,
		udpConn:       udpConn,
		quicConn:      nil,
		quicTransport: &quicTransport,
		quicConfig:    &quicConfig,
		config:        config,
	}, nil
}

func (c *Client) Close() {
	logger.Debug("Closing DoQ client")
	if c.udpConn != nil {
		c.udpConn.Close()
	}
}

func (c *Client) OpenConnection() error {
	logger.Debug("Opening DoQ connection to %s", c.targetAddr)
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

	if c.quicConn == nil {
		err := c.OpenConnection()
		if err != nil {
			return nil, err
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

	var quicStream quic.Stream
	quicStream, err = c.quicConn.OpenStream()
	if err != nil {
		logger.Debug("DoQ stream failed, reconnecting: %v", err)
		err = c.OpenConnection()
		if err != nil {
			return nil, err
		}
		quicStream, err = c.quicConn.OpenStream()
		if err != nil {
			logger.Error("DoQ failed to open stream after reconnect: %v", err)
			return nil, err
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

	return recvMsg, nil
}
