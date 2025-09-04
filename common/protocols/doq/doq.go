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

	tlsConfig := &tls.Config{
		ServerName:         config.Host,
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
		NextProtos:         []string{"doq"},
	}

	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Host, config.Port))
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target address: %w", err)
	}

	quicTransport := quic.Transport{
		Conn: udpConn,
	}

	quicConfig := quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

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
	if c.udpConn != nil {
		c.udpConn.Close()
	}
}

func (c *Client) OpenConnection() error {
	quicConn, err := c.quicTransport.DialEarly(context.Background(), c.targetAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		return err
	}

	c.quicConn = quicConn
	return nil
}

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {

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
		return nil, fmt.Errorf("doq: failed to pack message: %w", err)
	}

	var quicStream quic.Stream
	quicStream, err = c.quicConn.OpenStream()
	if err != nil {
		err = c.OpenConnection()
		if err != nil {
			return nil, err
		}
		quicStream, err = c.quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
	}

	var lengthPrefixedMessage bytes.Buffer
	err = binary.Write(&lengthPrefixedMessage, binary.BigEndian, uint16(len(packed)))
	if err != nil {
		return nil, fmt.Errorf("failed to write message length: %w", err)
	}
	_, err = lengthPrefixedMessage.Write(packed)
	if err != nil {
		return nil, fmt.Errorf("failed to write DNS message: %w", err)
	}

	_, err = quicStream.Write(lengthPrefixedMessage.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed writing to QUIC stream: %w", err)
	}
	// Indicate that no further data will be written from this side
	quicStream.Close()

	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(quicStream, lengthBuf)
	if err != nil {
		return nil, fmt.Errorf("failed reading response length: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBuf)
	if messageLength == 0 {
		return nil, fmt.Errorf("received zero-length message")
	}

	responseBuf := make([]byte, messageLength)
	_, err = io.ReadFull(quicStream, responseBuf)
	if err != nil {
		return nil, fmt.Errorf("failed reading response data: %w", err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return recvMsg, nil
}
