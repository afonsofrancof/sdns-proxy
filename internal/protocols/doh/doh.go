package doh

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/miekg/dns"
)

type DoHClient struct {
	tcpConn    *net.TCPConn
	tlsConn    *tls.Conn
	keyLogFile *os.File
	target     string
	path       string
	proxy      string
}

func New(target, path, proxy string) (*DoHClient, error) {

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
		// FIX: Actually check the domain name
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		KeyLogWriter:       keyLogFile,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("failed to execute the TLS handshake: %v", err)
	}

	return &DoHClient{tcpConn: tcpConn, keyLogFile: keyLogFile, tlsConn: tlsConn, target: target, path: path, proxy: proxy}, err

}

func (c *DoHClient) Close() {
	if c.tcpConn != nil {
		c.tcpConn.Close()
	}
	if c.keyLogFile != nil {
		c.keyLogFile.Close()
	}
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
}

func (c *DoHClient) Query(domain, queryType string, dnssec bool) error {

	DNSMessage, err := do53.NewDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequest("POST", "https://"+c.target+"/"+c.path, bytes.NewBuffer(DNSMessage))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Add("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	err = httpReq.Write(c.tlsConn)
	if err != nil {
		return fmt.Errorf("failed writing HTTP request: %v", err)
	}

	reader := bufio.NewReader(c.tlsConn)
	resp, err := http.ReadResponse(reader, httpReq)
	if err != nil {
		return fmt.Errorf("failed reading HTTP response: %v", err)
	}
	defer resp.Body.Close()

	responseBody := make([]byte, 4096)
	n, err := resp.Body.Read(responseBody)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed reading response body: %v", err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(responseBody[:n])
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %v", err)
	}

	// TODO: Check if the response had no errors or TD bit set

	for _, answer := range recvMsg.Answer {
		fmt.Println(answer.String())
	}

	return nil
}
