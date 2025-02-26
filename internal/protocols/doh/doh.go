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
	"golang.org/x/net/dns/dnsmessage"
)

func Run(domain, queryType, server, path, proxy string, dnssec bool) error {

	DNSMessage, err := do53.MakeDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	// Step 1 - Establish a TCP Connection
	tcpConn, err := net.Dial("tcp", server)
	if err != nil {
		return fmt.Errorf("failed to establish TCP connection: %v", err)
	}
	defer tcpConn.Close()

	// Step 2 - Upgrade it to a TLS Connection

	// Temporary keylog file to allow traffic inspection
	keyLogFile, err := os.OpenFile(
		"tls-key-log.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("failed opening key log file: %v", err)
	}
	defer keyLogFile.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		KeyLogWriter:       keyLogFile,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return fmt.Errorf("failed to execute the TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Step 3 - Create an HTTP request with the do53 message in the body
	httpReq, err := http.NewRequest("POST", "https://"+server+"/"+path, bytes.NewBuffer(DNSMessage))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Add("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	err = httpReq.Write(tlsConn)
	if err != nil {
		return fmt.Errorf("failed writing HTTP request: %v", err)
	}

	reader := bufio.NewReader(tlsConn)
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

	// Parse the response
	var parser dnsmessage.Parser
	header, err := parser.Start(responseBody[:n])
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %v", err)
	}

	fmt.Printf("DNS Response Header:\n")
	fmt.Printf("  ID: %d\n", header.ID)
	fmt.Printf("  Response: %v\n", header.Response)
	fmt.Printf("  RCode: %v\n", header.RCode)

	// Skip all questions before reading answers
	err = parser.SkipAllQuestions()
	if err != nil {
		return fmt.Errorf("failed to skip questions: %v", err)
	}

	// Parse answers
	fmt.Printf("\nAnswers:\n")
	answers, err := parser.AllAnswers()

	for i, answer := range answers {

		if err != nil {
			return fmt.Errorf("failed to parse answer %d: %v", i, err)
		}

		fmt.Printf("  Answer %d:\n", i+1)
		fmt.Printf("    Name: %v\n", answer.Header.Name)
		fmt.Printf("    Type: %v\n", answer.Header.Type)
		fmt.Printf("    TTL: %v seconds\n", answer.Header.TTL)

		// Handle different record types
		switch answer.Header.Type {
		case dnsmessage.TypeA:
			if r, ok := answer.Body.(*dnsmessage.AResource); ok {
				fmt.Printf("    IPv4: %d.%d.%d.%d\n", r.A[0], r.A[1], r.A[2], r.A[3])
			}
		case dnsmessage.TypeAAAA:
			if r, ok := answer.Body.(*dnsmessage.AAAAResource); ok {
				ip := r.AAAA
				fmt.Printf("    IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
					ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
					ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
			}
		case dnsmessage.TypeCNAME:
			if r, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
				fmt.Printf("    CNAME: %v\n", r.CNAME)
			}
		case dnsmessage.TypeMX:
			if r, ok := answer.Body.(*dnsmessage.MXResource); ok {
				fmt.Printf("    Preference: %v\n", r.Pref)
				fmt.Printf("    MX: %v\n", r.MX)
			}
		case dnsmessage.TypeTXT:
			if r, ok := answer.Body.(*dnsmessage.TXTResource); ok {
				fmt.Printf("    TXT: %v\n", r.TXT)
			}
		default:
			fmt.Printf("    [Unsupported record type]\n")
		}
	}

	return nil
}
