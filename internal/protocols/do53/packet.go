package do53

import (
	"fmt"

	"golang.org/x/net/dns/dnsmessage"
)

func MakeDNSMessage(domain string, queryType string) ([]byte, error) {
	messageHeader := dnsmessage.Header{
		ID:               1234, // FIX: Use a random ID
		Response:         false,
		OpCode:           dnsmessage.OpCode(0),
		RecursionDesired: true,
	}

	messageBuilder := dnsmessage.NewBuilder(nil, messageHeader)
	queryName, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create query name: %v", err)
	}

	// Determine query type
	var queryTypeValue dnsmessage.Type
	switch queryType {
	case "A":
		queryTypeValue = dnsmessage.TypeA
	case "AAAA":
		queryTypeValue = dnsmessage.TypeAAAA
	case "MX":
		queryTypeValue = dnsmessage.TypeMX
	case "CNAME":
		queryTypeValue = dnsmessage.TypeCNAME
	case "TXT":
		queryTypeValue = dnsmessage.TypeTXT
	default:
		queryTypeValue = dnsmessage.TypeA
	}

	messageQuestion := dnsmessage.Question{
		Name:  queryName,
		Type:  queryTypeValue,
		Class: dnsmessage.ClassINET,
	}

	err = messageBuilder.StartQuestions()
	if err != nil {
		return nil, err
	}
	err = messageBuilder.Question(messageQuestion)
	if err != nil {
		return nil, fmt.Errorf("failed to add question: %v", err)
	}

	message, err := messageBuilder.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to build message: %v", err)
	}
	return message, nil
}
