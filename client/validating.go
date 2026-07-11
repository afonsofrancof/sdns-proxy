package client

import (
	"fmt"

	"github.com/afonsofrancof/sdns-proxy/common/dnssec"
	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

type ValidatingDNSClient struct {
	client    DNSClient
	validator *dnssec.Validator
	options   Options
}

func NewValidating(base DNSClient, opts Options) DNSClient {
	logger.Debug("Wrapping base client with DNSSEC validator (AuthoritativeDNSSEC: %v)", opts.AuthoritativeDNSSEC)

	var validator *dnssec.Validator
	if opts.AuthoritativeDNSSEC {
		validator = dnssec.NewAuthoritativeValidator()
	} else {
		validator = dnssec.NewValidator(func(m *dns.Msg) (*dns.Msg, error) { _, r, e := base.Query(m); return r, e })
	}

	return &ValidatingDNSClient{
		client:    base,
		validator: validator,
		options:   opts,
	}
}

func (v *ValidatingDNSClient) LastValidation() dnssec.ValidationStats {
	if v.validator == nil {
		return dnssec.ValidationStats{}
	}
	return v.validator.TakeStats()
}

func (v *ValidatingDNSClient) Query(msg *dns.Msg) (*dns.Msg, *dns.Msg, error) {
	if len(msg.Question) > 0 {
		question := msg.Question[0]
		logger.Debug("ValidatingDNSClient query: %s %s (DNSSEC: %v, AuthoritativeDNSSEC: %v, ValidateOnly: %v, StrictValidation: %v)",
			question.Name, dns.TypeToString[question.Qtype], v.options.DNSSEC, v.options.AuthoritativeDNSSEC, v.options.ValidateOnly, v.options.StrictValidation)
	}

	// Query the base client
	sent, response, err := v.client.Query(msg)
	if err != nil {
		logger.Debug("Base client query failed: %v", err)
		return sent, nil, err
	}

	if len(msg.Question) == 0 {
		logger.Debug("No questions in message, skipping DNSSEC validation")
		return sent, response, nil
	}

	question := sent.Question[0]
	qname := question.Name
	qtype := question.Qtype

	logger.Debug("Starting DNSSEC validation for %s %s", qname, dns.TypeToString[qtype])

	validationErr := v.validator.ValidateResponse(response, qname, qtype)

	if validationErr != nil {
		// Unsigned domain: return the response unless validate-only is set.
		if validationErr == dnssec.ErrResourceNotSigned {
			logger.Debug("Domain %s is not DNSSEC signed", qname)
			if v.options.ValidateOnly {
				logger.Error("Domain %s is not DNSSEC signed (ValidateOnly mode)", qname)
				return sent, nil, fmt.Errorf("domain %s is not DNSSEC signed", qname)
			}
			return sent, response, nil
		}

		// Any other validation error.
		logger.Debug("DNSSEC validation failed for %s: %v", qname, validationErr)
		if v.options.StrictValidation {
			logger.Error("DNSSEC validation failed for %s (strict mode): %v", qname, validationErr)
			return sent, nil, fmt.Errorf("DNSSEC validation failed for %s: %w", qname, validationErr)
		}
		logger.Debug("DNSSEC validation failed for %s (non-strict mode), returning response anyway: %v", qname, validationErr)
		return sent, response, nil
	}

	logger.Debug("DNSSEC validation successful for %s %s", qname, dns.TypeToString[qtype])
	return sent, response, nil
}

func (v *ValidatingDNSClient) Close() {
	logger.Debug("Closing ValidatingDNSClient")
	if v.client != nil {
		v.client.Close()
	}
}
