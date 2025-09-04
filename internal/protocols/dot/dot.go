package dot

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	Host   string
	Port   string
	DNSSEC bool
	Debug  bool
}

type Client struct {
	config Config

	serverAddr *net.TCPAddr

	tcpConn    *net.TCPConn
	tlsConn    *tls.Conn
	tlsConfig  *tls.Config
	keyLogFile *os.File

	sendChannel chan *dns.Msg

	responseChannels map[uint16]chan *dns.Msg
	responseMutex    *sync.Mutex
}

func New(config Config) (*Client, error) {
	serverAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(config.Host, config.Port))
	if err != nil {
		return nil, fmt.Errorf("dot: failed to resolve TCP address %q: %w", config.Host, err)
	}

	var keyLogFile *os.File
	if config.Debug {
		keyLogFile, err = os.OpenFile(
			"tls-key-log.txt",
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0600,
		)
		if err != nil {
			log.Printf("dot: failed opening TLS key log file: %v", err)
			keyLogFile = nil
		}
	}

	tlsConfig := &tls.Config{
		ServerName:         serverAddr.IP.String(),
		MinVersion:         tls.VersionTLS12,
		KeyLogWriter:       keyLogFile,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	client := &Client{
		config:     config,
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		keyLogFile: keyLogFile,
	}

	go client.receiveLoop()

	return client, nil
}

func (c *Client) Close() {
	if c.tlsConn != nil {
		c.tlsConn.Close()
		c.tlsConn = nil
	}

	if c.tcpConn != nil {
		c.tcpConn.Close()
		c.tcpConn = nil
	}

	if c.keyLogFile != nil {
		c.keyLogFile.Close()
		c.keyLogFile = nil
	}
}

func (c *Client) receiveLoop() {

	lengthBuffer := make([]byte, 2)
	buffer := make([]byte, dns.MaxMsgSize)

	for {
		msgSize, err := io.ReadFull(c.tlsConn, lengthBuffer)
		if err != nil {
			log.Printf("doh: failed to read the DNS message's size: %s", err.Error())
			// FIX: HANDLE RECONNECTION
		}
		n, err := io.ReadFull(c.tlsConn, buffer[:msgSize])
		if err != nil {
			log.Printf("doh: failed to read the DNS message: %s", err.Error())
			// FIX: HANDLE RECONNECTION
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

func (c *Client) connect(ctx context.Context) error {
	tcpConn, err := net.DialTCP("tcp", nil, c.serverAddr)
	if err != nil {
		return fmt.Errorf("dot: failed to establish TCP connection: %w", err)
	}

	c.tcpConn.SetKeepAlive(true)
	c.tcpConn.SetKeepAlivePeriod(1 * time.Minute)

	tlsConn := tls.Client(c.tcpConn, c.tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		c.tcpConn.Close()
		c.tcpConn = nil
		return fmt.Errorf("dot: failed to execute the TLS handshake: %w", err)
	}

	c.tlsConn = tlsConn

	log.Println("dot: TCP/TLS connection established successfully.")

	return nil
}

func (c *Client) Query(domain string, queryType uint16) (*dns.Msg, error) {
	//TODO
}
