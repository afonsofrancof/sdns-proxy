package do53

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type Do53Client struct {
	udpConn *net.UDPConn
}

func New(dest string) (*Do53Client, error) {

	udpAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP connection: %v", err)
	}
	return &Do53Client{udpConn: udpConn}, nil
}

func (c *Do53Client) Close() {
	if c.udpConn != nil {
		c.udpConn.Close()
	}
}

func (c *Do53Client) Query(domain, queryType, dest string, dnssec bool) error {

	message, err := NewDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	_, err = c.udpConn.Write(message)
	if err != nil {
		return fmt.Errorf("failed to send DNS query: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := c.udpConn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read DNS response: %v", err)
	}

	recvMsg := new(dns.Msg)
	err = recvMsg.Unpack(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %v", err)
	}

	// TODO: Check if the response had no errors or TD bit set

	for _, answer := range recvMsg.Answer {
		fmt.Println(answer.String())
	}

	return nil
}
