package doq

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type DoQClient struct {
	target        string
	keyLogFile    *os.File
	tlsConfig     *tls.Config
}

func New(target string) (*DoQClient, error) {
	keyLogFile, err := os.OpenFile(
		"tls-key-log.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("failed opening key log file: %v", err)
	}

	tlsConfig := &tls.Config{
		// FIX: Actually check the domain name
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		KeyLogWriter:       keyLogFile,
		NextProtos:         []string{"doq"},
	}

	return &DoQClient{
		target:        target,
		keyLogFile:    keyLogFile,
		tlsConfig:     tlsConfig,
	}, nil
}

func (c *DoQClient) Close() {
	if c.keyLogFile != nil {
		c.keyLogFile.Close()
	}
}

func (c *DoQClient) Query(domain, queryType string, dnssec bool) error {
	quicConn, err := quic.DialAddr(context.Background(), c.target, c.tlsConfig, &quic.Config{})
	if err != nil {
		return fmt.Errorf("failed to establish QUIC connection: %v", err)
	}
	defer quicConn.CloseWithError(0, "")

	DNSMessage, err := do53.NewDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	quicStream, err := quicConn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to opening QUIC stream: %v", err)
	}
	defer quicStream.Close()

	var lengthPrefixedMessage bytes.Buffer
	err = binary.Write(&lengthPrefixedMessage, binary.BigEndian, uint16(len(DNSMessage)))
	if err != nil {
		return fmt.Errorf("failed to write message length: %v", err)
	}
	_, err = lengthPrefixedMessage.Write(DNSMessage)
	if err != nil {
		return fmt.Errorf("failed to write DNS message: %v", err)
	}

	_, err = quicStream.Write(lengthPrefixedMessage.Bytes())
	if err != nil {
		return fmt.Errorf("failed writing to QUIC stream: %v", err)
	}

	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(quicStream, lengthBuf)
	if err != nil {
		return fmt.Errorf("failed reading response length: %v", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBuf)
	if messageLength == 0 {
		return fmt.Errorf("received zero-length message")
	}

	responseBuf := make([]byte, messageLength)
	_, err = io.ReadFull(quicStream, responseBuf)
	if err != nil {
		return fmt.Errorf("failed reading response data: %v", err)
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
