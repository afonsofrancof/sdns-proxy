package do53

import (
	"github.com/miekg/dns"
)

func NewDNSMessage(domain string, queryType string) ([]byte, error) {

	// TODO: Move this somewhere else and receive the type already parsed
	var queryTypeValue uint16
	switch queryType {
	case "A":
		queryTypeValue = dns.TypeA
	case "AAAA":
		queryTypeValue = dns.TypeAAAA
	case "MX":
		queryTypeValue = dns.TypeMX
	case "CNAME":
		queryTypeValue = dns.TypeCNAME
	case "TXT":
		queryTypeValue = dns.TypeTXT
	default:
		queryTypeValue = dns.TypeA
	}

	message := new(dns.Msg)

	message.Id = dns.Id()
	message.Response = false
	message.Opcode = dns.OpcodeQuery
	message.Question = make([]dns.Question, 1)
	message.Question[0] = dns.Question{Name: domain, Qtype: uint16(queryTypeValue), Qclass: dns.ClassINET}
	message.Compress = true
	wireMsg, err := message.Pack()
	if err != nil {
		return nil, err
	}

	return wireMsg, nil
}
