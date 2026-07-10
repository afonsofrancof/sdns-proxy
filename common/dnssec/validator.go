package dnssec

import (
	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

type ValidationStats struct {
	Queries       int
	BytesSent     int
	BytesReceived int
	Validated     bool
}

type SendFunc func(msg *dns.Msg) (*dns.Msg, error)

type walker interface {
	validate(answer *RRSet, qname string, qtype uint16) error
	stats() ValidationStats
	resetStats()
}

type Validator struct {
	walker walker
}

func NewValidator(send SendFunc) *Validator {
	return &Validator{walker: newTrustWalker(send)}
}

func NewAuthoritativeValidator() *Validator {
	return &Validator{walker: newIterativeWalker()}
}

func (v *Validator) ValidateResponse(msg *dns.Msg, qname string, qtype uint16) error {
	if msg == nil || len(msg.Answer) == 0 {
		return ErrNoResult
	}

	answer := extractRRSet(msg, qname, qtype)
	if answer.IsEmpty() {
		return ErrNoResult
	}
	if !answer.IsSigned() {
		return ErrResourceNotSigned
	}
	if err := answer.CheckHeaderIntegrity(dns.Fqdn(qname)); err != nil {
		return err
	}

	logger.Debug("Validating %s %s (signer: %s)", qname, dns.TypeToString[qtype], answer.SignerName())
	return v.walker.validate(answer, qname, qtype)
}

func (v *Validator) TakeStats() ValidationStats {
	s := v.walker.stats()
	v.walker.resetStats()
	return s
}

func extractRRSet(msg *dns.Msg, name string, qtype uint16) *RRSet {
	if msg == nil {
		return NewRRSet()
	}
	return extractRRSetFrom(msg.Answer, name, qtype)
}

func extractRRSetFrom(rrs []dns.RR, name string, qtype uint16) *RRSet {
	set := NewRRSet()
	fq := dns.Fqdn(name)
	for _, rr := range rrs {
		switch t := rr.(type) {
		case *dns.RRSIG:
			if t.TypeCovered == qtype && dns.Fqdn(t.Header().Name) == fq {
				set.RRSig = t
			}
		default:
			if rr.Header().Rrtype == qtype && dns.Fqdn(rr.Header().Name) == fq {
				set.RRs = append(set.RRs, rr)
			}
		}
	}
	return set
}
