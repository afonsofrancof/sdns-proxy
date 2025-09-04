package doq

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type Client struct {
	targetAddr    *net.UDPAddr
	keyLogFile    *os.File
	tlsConfig     *tls.Config
	udpConn       *net.UDPConn
	quicConn      quic.Connection
	quicTransport *quic.Transport
	quicConfig    *quic.Config
}

func New(target string) (*Client, error) {
	keyLogFile, err := os.OpenFile(
		"tls-key-log.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("failed opening key log file: %w", err)
	}

	tlsConfig := &tls.Config{
		// FIX: Actually check the domain name
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
		KeyLogWriter:       keyLogFile,
		NextProtos:         []string{"doq"},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:6000")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target address: %w", err)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target address: %w", err)
	}

	quicTransport := quic.Transport{
		Conn: udpConn,
	}

	quicConfig := quic.Config{
		// Use the default value of 30 seconds
		MaxIdleTimeout: 30 * time.Second,
	}

	return &Client{
		targetAddr:    targetAddr,
		keyLogFile:    keyLogFile,
		tlsConfig:     tlsConfig,
		udpConn:       udpConn,
		quicConn:      nil,
		quicTransport: &quicTransport,
		quicConfig:    &quicConfig,
	}, nil
}

func (c *Client) Close() {
	if c.keyLogFile != nil {
		c.keyLogFile.Close()
	}
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

func (c *Client) Query(domain, queryType string, dnssec bool) error {

	if c.quicConn == nil {
		err := c.OpenConnection()
		if err != nil {
			return err
		}
	}

	DNSMessage, err := do53.NewDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	var quicStream quic.Stream
	quicStream, err = c.quicConn.OpenStream()
	if err != nil {
		err = c.OpenConnection()
		if err != nil {
			return err
		}
		quicStream, err = c.quicConn.OpenStream()
		if err != nil {
			return err
		}
	}

	var lengthPrefixedMessage bytes.Buffer
	err = binary.Write(&lengthPrefixedMessage, binary.BigEndian, uint16(len(DNSMessage)))
	if err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}
	_, err = lengthPrefixedMessage.Write(DNSMessage)
	if err != nil {
		return fmt.Errorf("failed to write DNS message: %w", err)
	}

	_, err = quicStream.Write(lengthPrefixedMessage.Bytes())
	if err != nil {
		return fmt.Errorf("failed writing to QUIC stream: %w", err)
	}
	// Indicate that no further data will be written from this side
	quicStream.Close()

	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(quicStream, lengthBuf)
	if err != nil {
		return fmt.Errorf("failed reading response length: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBuf)
	if messageLength == 0 {
		return fmt.Errorf("received zero-length message")
	}

	responseBuf := make([]byte, messageLength)
	_, err = io.ReadFull(quicStream, responseBuf)
	if err != nil {
		return fmt.Errorf("failed reading response data: %w", err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBuf)
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %w", err)
	}

	// TODO: Check if the response had no errors or TD bit set

	fmt.Println(c.quicConn.ConnectionState().Used0RTT)
	for _, answer := range recvMsg.Answer {
		fmt.Println(answer.String())
	}

	return nil
}
