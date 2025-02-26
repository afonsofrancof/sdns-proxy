package do53

import (
	"fmt"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

func Run(domain, queryType, dest string, dnssec bool) error {

	message, err := MakeDNSMessage(domain, queryType)
	if err != nil {
		return err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP connection: %v", err)
	}
	defer udpConn.Close()

	_, err = udpConn.Write(message)
	if err != nil {
		return fmt.Errorf("failed to send DNS query: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := udpConn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read DNS response: %v", err)
	}

	var parser dnsmessage.Parser
	_, err = parser.Start(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse DNS response: %v", err)
	}

	// TODO: Check if the response had no errors or TD bit set

	err = parser.SkipAllQuestions()
	if err != nil {
		return fmt.Errorf("failed to skip questions: %v", err)
	}

	answers, err := parser.AllAnswers()
	if err != nil {
		return err
	}

	for _, answer := range answers {
		fmt.Println(answer.GoString())
	}

	return nil
}

