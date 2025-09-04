package do53

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/miekg/dns"
)

type Config struct {
	HostAndPort string
	DNSSEC      bool
}

type Client struct {
	udpAddr *net.UDPAddr
	conn    *net.UDPConn

	responseChannels map[uint16]chan *dns.Msg
	responseMutex          *sync.Mutex

	config Config
}

func New(config Config) (*Client, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.HostAndPort)
	if err != nil {
		return nil, fmt.Errorf("do53: failed to resolve UDP address %q: %w", config.HostAndPort, err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("do53: failed to dial UDP connection to %s: %w", config.HostAndPort, err)
	}

	responseChannels := map[uint16]chan *dns.Msg{}
	rcMutex := new(sync.Mutex)

	client := &Client{
		udpAddr:          udpAddr,
		conn:             conn,
		responseChannels: responseChannels,
		responseMutex:          rcMutex,
		config:           config,
	}

	go client.receiveLoop()

	return client, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) receiveLoop() {

	buffer := make([]byte, dns.MaxMsgSize)

	for {
		// Reads one UDP Datagram
		n, err := c.conn.Read(buffer)
		if err != nil {
			log.Printf("do53: failed to read DNS response: %s", err.Error())
		}

		recvMsg := new(dns.Msg)
		err = recvMsg.Unpack(buffer[:n])
		if err != nil {
			log.Printf("do53: failed to unpack DNS response: %s", err.Error())
			continue
		}

		c.responseMutex.Lock()
		respChan, ok := c.responseChannels[recvMsg.Id]
		delete(c.responseChannels, recvMsg.Id)
		c.responseMutex.Unlock()

		if ok {
			respChan <- recvMsg
		} else {
			log.Printf("Receiver: Received DNS response for unknown or already processed msg ID: %v\n", recvMsg.Id)
		}
	}

}

func (c *Client) Query(domain string, queryType uint16) (*dns.Msg, error) {

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)
	msg.Id = dns.Id()
	msg.RecursionDesired = true

	if c.config.DNSSEC {
		msg.SetEdns0(4096, true)
	}

	respChan := make(chan *dns.Msg)

	c.responseMutex.Lock()
	c.responseChannels[msg.Id] = respChan
	c.responseMutex.Unlock()

	packedMsg, err := msg.Pack()
	if err != nil {
		c.responseMutex.Lock()
		delete(c.responseChannels, msg.Id)
		c.responseMutex.Unlock()
		return nil, fmt.Errorf("do53: failed to pack DNS message: %w", err)
	}

	_, err = c.conn.Write(packedMsg)
	if err != nil {
		c.responseMutex.Lock()
		delete(c.responseChannels, msg.Id)
		c.responseMutex.Unlock()
		return nil, fmt.Errorf("do53: failed to send DNS query: %w", err)
	}

	recvMsg := <-respChan

	return recvMsg, nil
}
