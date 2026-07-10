package dnssec

import (
	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

// trustWalker validates bottom-up.
// The parent of each zone is discovered from the DS record's RRSIG signer name.
type trustWalker struct {
	send SendFunc
	st   ValidationStats
}

func newTrustWalker(send SendFunc) *trustWalker {
	return &trustWalker{send: send}
}

func (w *trustWalker) stats() ValidationStats { return w.st }
func (w *trustWalker) resetStats()            { w.st = ValidationStats{} }

func (w *trustWalker) ask(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	if b, err := m.Pack(); err == nil {
		w.st.BytesSent += len(b)
	}
	w.st.Queries++

	resp, err := w.send(m)
	logger.Debug("trust walker got %s %s: %d answers", name, dns.TypeToString[qtype], len(resp.Answer))
	if err == nil && resp != nil {
		if b, perr := resp.Pack(); perr == nil {
			w.st.BytesReceived += len(b)
		}
	}
	return resp, err
}

func (w *trustWalker) validate(answer *RRSet, qname string, qtype uint16) error {
	signer := dns.Fqdn(answer.SignerName())
	if signer == "" {
		return ErrResourceNotSigned
	}

	// Fetch the signing zone's keys and verify the answer against them.
	signingZone, err := w.fetchSelfSignedKeys(signer)
	if err != nil {
		return err
	}
	if err := signingZone.VerifyRRSIG(answer); err != nil {
		logger.Debug("answer RRSIG verification failed for %s: %v", qname, err)
		return ErrInvalidRRsig
	}

	// Walk up: signing zone -> ... -> root, verifying DS linkage each step.
	current := signingZone
	name := signer
	for name != "." {
		dsResp, err := w.ask(name, dns.TypeDS)
		if err != nil {
			return err
		}
		dsSet := extractRRSet(dsResp, name, dns.TypeDS)
		if dsSet.IsEmpty() || !dsSet.IsSigned() {
			return ErrDsNotAvailable
		}

		// The DS must match the current zone's key.
		if err := current.VerifyDS(dsSet.RRs); err != nil {
			return err
		}

		// The parent zone is whoever signed the DS RRset.
		parentName := dns.Fqdn(dsSet.SignerName())

		var parent *SignedZone
		if parentName == "." {
			parent, err = w.fetchRoot()
		} else {
			parent, err = w.fetchSelfSignedKeys(parentName)
		}
		if err != nil {
			return err
		}

		// The parent must have signed the DS RRset.
		if err := parent.VerifyRRSIG(dsSet); err != nil {
			logger.Debug("DS RRSIG verification failed for %s: %v", name, err)
			return ErrInvalidRRsig
		}

		current = parent
		name = parentName
	}

	w.st.Validated = true
	return nil
}

func (w *trustWalker) fetchSelfSignedKeys(zoneName string) (*SignedZone, error) {
	resp, err := w.ask(zoneName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	keyset := extractRRSet(resp, zoneName, dns.TypeDNSKEY)
	if keyset.IsEmpty() || !keyset.IsSigned() {
		return nil, ErrDnskeyNotAvailable
	}

	zone := NewSignedZone(zoneName)
	zone.DNSKey = keyset
	for _, rr := range keyset.RRs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			zone.AddPubKey(k)
		}
	}
	if err := zone.VerifyRRSIG(keyset); err != nil {
		return nil, err
	}
	return zone, nil
}

// fetchRoot fetches the root DNSKEY set and verifies it against the anchor.
func (w *trustWalker) fetchRoot() (*SignedZone, error) {
	resp, err := w.ask(".", dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	keyset := extractRRSet(resp, ".", dns.TypeDNSKEY)
	return verifyRootAnchor(keyset)
}
