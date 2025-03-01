package dot

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/miekg/dns"
)

type DoTClient struct {
	tcpConn    *net.TCPConn
	tlsConn    *tls.Conn
	keyLogFile *os.File
}

func New(target string) (*DoTClient, error) {

	tcpAddr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TCP address: %v", err)
	}

	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TCP connection: %v", err)
	}

	keyLogFile, err := os.OpenFile(
		"tls-key-log.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("failed opening key log file: %v", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		KeyLogWriter:       keyLogFile,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("failed to execute the TLS handshake: %v", err)
	}

	return &DoTClient{tcpConn: tcpConn, tlsConn: tlsConn, keyLogFile: keyLogFile}, nil
}

func (c *DoTClient) Close() {
	if c.tcpConn != nil {
		c.tcpConn.Close()
	}
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
	if c.keyLogFile != nil {
		c.keyLogFile.Close()
	}
}

func (c *DoTClient) Query(domain, queryType, target string, dnssec bool) error {

	DNSMessage, err := do53.NewDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	var lengthPrefixedMessage bytes.Buffer
	err = binary.Write(&lengthPrefixedMessage, binary.BigEndian, uint16(len(DNSMessage)))
	if err != nil {
		return fmt.Errorf("failed to write message length: %v", err)
	}
	_, err = lengthPrefixedMessage.Write(DNSMessage)
	if err != nil {
		return fmt.Errorf("failed to write DNS message: %v", err)
	}

	_, err = c.tlsConn.Write(lengthPrefixedMessage.Bytes())
	if err != nil {
		return fmt.Errorf("failed writing TLS request: %v", err)
	}

	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(c.tlsConn, lengthBuf)
	if err != nil {
		return fmt.Errorf("failed reading response length: %v", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBuf)
	if messageLength == 0 {
		return fmt.Errorf("received zero-length message")
	}

	responseBuf := make([]byte, messageLength)
	_, err = io.ReadFull(c.tlsConn, responseBuf)
	if err != nil {
		return fmt.Errorf("failed reading TLS response: %v", err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBuf)
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %v", err)
	}

	// TODO: Check if the response had no errors or TD bit set

	for _, answer := range recvMsg.Answer {
		fmt.Println(answer.String())
	}

	return nil
}
