package dnssec

// CODE ADAPTED FROM THIS

// ISC License
//
// Copyright (c) 2012-2016 Peter Banik <peter@froggle.org>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
// ./common/dnssec/validator.go

import (
	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

type Validator struct {
	queryFunc func(string, uint16) (*dns.Msg, error)
}

func NewValidator(queryFunc func(string, uint16) (*dns.Msg, error)) *Validator {
	return &Validator{
		queryFunc: queryFunc,
	}
}

func (v *Validator) ValidateResponse(msg *dns.Msg, qname string, qtype uint16) error {
	logger.Debug("Starting DNSSEC validation for %s %s", qname, dns.TypeToString[qtype])

	if msg == nil || len(msg.Answer) == 0 {
		logger.Debug("No result for %s %s", qname, dns.TypeToString[qtype])
		return ErrNoResult
	}

	// Extract RRSet from response
	rrset := NewRRSet()
	for _, rr := range msg.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			if t.TypeCovered == qtype {
				rrset.RRSig = t
				logger.Debug("Found RRSIG for %s %s (keytag: %d)", qname, dns.TypeToString[qtype], t.KeyTag)
			}
		default:
			if rr.Header().Rrtype == qtype {
				rrset.RRs = append(rrset.RRs, rr)
				logger.Debug("Found RR for %s %s: %s", qname, dns.TypeToString[qtype], rr.String())
			}
		}
	}

	if rrset.IsEmpty() {
		logger.Debug("Empty RRSet for %s %s", qname, dns.TypeToString[qtype])
		return ErrNoResult
	}

	if !rrset.IsSigned() {
		logger.Debug("RRSet for %s %s is not signed", qname, dns.TypeToString[qtype])
		return ErrResourceNotSigned
	}

	// Check header integrity
	if err := rrset.CheckHeaderIntegrity(qname); err != nil {
		logger.Debug("Header integrity check failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
		return err
	}

	// Build and verify authentication chain
	signerName := rrset.SignerName()
	logger.Debug("Building authentication chain for signer: %s", signerName)
	authChain := NewAuthenticationChain()

	if err := authChain.Populate(signerName, v.queryFunc); err != nil {
		logger.Debug("Cannot populate authentication chain for %s: %v", signerName, err)
		return err
	}

	if err := authChain.Verify(rrset); err != nil {
		logger.Debug("DNSSEC validation failed for %s %s: %v", qname, dns.TypeToString[qtype], err)
		return err
	}

	logger.Debug("DNSSEC validation successful for %s %s", qname, dns.TypeToString[qtype])
	return nil
}

func NewValidatorWithAuthoritativeQueries() *Validator {
	querier := NewAuthoritativeQuerier()
	return NewValidator(querier.QueryAuthoritative)
}
