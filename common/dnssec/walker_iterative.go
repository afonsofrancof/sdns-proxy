package dnssec

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

// iterativeWalker validates top-down.
type iterativeWalker struct {
	client  *dns.Client
	st      ValidationStats
	ipCache map[string]string
}

func newIterativeWalker() *iterativeWalker {
	return &iterativeWalker{
		client:  &dns.Client{Timeout: 5 * time.Second},
		ipCache: make(map[string]string),
	}
}

func (w *iterativeWalker) stats() ValidationStats { return w.st }
func (w *iterativeWalker) resetStats()            { w.st = ValidationStats{} }

func (w *iterativeWalker) exchange(server, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.RecursionDesired = false

	if b, err := m.Pack(); err == nil {
		w.st.BytesSent += len(b)
	}
	w.st.Queries++

	resp, _, err := w.client.Exchange(m, server)
	if err == nil && resp != nil {
		if b, perr := resp.Pack(); perr == nil {
			w.st.BytesReceived += len(b)
		}
	}
	return resp, err
}

func (w *iterativeWalker) queryAny(servers []string, name string, qtype uint16) (*dns.Msg, error) {
	var lastErr error
	for _, s := range servers {
		resp, err := w.exchange(s, name, qtype)
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no response from servers")
	}
	return nil, lastErr
}

func (w *iterativeWalker) validate(answer *RRSet, qname string, qtype uint16) error {
	current, servers, err := w.trustRoot()
	if err != nil {
		return err
	}
	currentServers := servers

	// Follow delegations from the root toward qname.
	for {
		resp, err := w.queryAny(currentServers, qname, qtype)
		if err != nil {
			return err
		}

		// Authoritative answer for the record: verify it and finish.
		if hasAnswer(resp, qname, qtype) {
			ans := extractRRSet(resp, qname, qtype)
			if ans.IsEmpty() || !ans.IsSigned() {
				return ErrResourceNotSigned
			}
			if err := current.VerifyRRSIG(ans); err != nil {
				logger.Debug("answer RRSIG verification failed for %s: %v", qname, err)
				return ErrInvalidRRsig
			}
			w.st.Validated = true
			return nil
		}

		// Otherwise expect a referral to a child zone.
		childZone, childServers, dsSet, err := w.parseReferral(resp)
		if err != nil {
			return err
		}
		if dsSet.IsEmpty() || !dsSet.IsSigned() {
			// No signed DS at the cut means the child is not securely
			// delegated; the chain cannot continue.
			return ErrDsNotAvailable
		}

		// The DS must be signed by the current (parent) zone.
		if err := current.VerifyRRSIG(dsSet); err != nil {
			logger.Debug("DS RRSIG verification failed for %s: %v", childZone, err)
			return ErrInvalidRRsig
		}

		// Fetch the child DNSKEY and verify it matches the DS.
		child, err := w.fetchZoneKeys(childServers, childZone)
		if err != nil {
			return err
		}
		if err := child.VerifyDS(dsSet.RRs); err != nil {
			return err
		}

		current = child
		currentServers = childServers
	}
}

func (w *iterativeWalker) trustRoot() (*SignedZone, []string, error) {
	var lastErr error
	for _, server := range rootHints {
		resp, err := w.exchange(server, ".", dns.TypeDNSKEY)
		if err != nil || resp == nil {
			lastErr = err
			continue
		}
		keyset := extractRRSet(resp, ".", dns.TypeDNSKEY)
		zone, verr := verifyRootAnchor(keyset)
		if verr != nil {
			lastErr = verr
			continue
		}
		return zone, rootHints, nil
	}
	if lastErr == nil {
		lastErr = ErrDnskeyNotAvailable
	}
	return nil, nil, fmt.Errorf("root trust anchor validation failed: %w", lastErr)
}

func (w *iterativeWalker) fetchZoneKeys(servers []string, zoneName string) (*SignedZone, error) {
	resp, err := w.queryAny(servers, zoneName, dns.TypeDNSKEY)
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

func (w *iterativeWalker) parseReferral(msg *dns.Msg) (childZone string, childServers []string, ds *RRSet, err error) {
	if msg == nil {
		return "", nil, nil, fmt.Errorf("nil referral")
	}

	// The delegated zone is the owner name of the NS records in the authority
	// section. Collect NS names per zone.
	nsNamesByZone := map[string][]string{}
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			z := dns.Fqdn(ns.Header().Name)
			nsNamesByZone[z] = append(nsNamesByZone[z], ns.Ns)
		}
	}
	if len(nsNamesByZone) == 0 {
		return "", nil, nil, fmt.Errorf("no referral NS records present")
	}

	// There should be exactly one delegated zone in a referral.
	var nsNames []string
	for z, names := range nsNamesByZone {
		childZone = z
		nsNames = names
		break
	}

	ds = extractRRSetFrom(msg.Ns, childZone, dns.TypeDS)
	childServers = w.resolveNS(nsNames, msg.Extra)
	if len(childServers) == 0 {
		return "", nil, nil, fmt.Errorf("could not resolve nameservers for %s", childZone)
	}
	return childZone, childServers, ds, nil
}

func (w *iterativeWalker) resolveNS(nsNames []string, extra []dns.RR) []string {
	glue := map[string]string{}
	for _, rr := range extra {
		if a, ok := rr.(*dns.A); ok {
			glue[dns.Fqdn(a.Header().Name)] = a.A.String()
		}
	}

	var servers []string
	for _, ns := range nsNames {
		fq := dns.Fqdn(ns)
		if ip, ok := glue[fq]; ok {
			servers = append(servers, net.JoinHostPort(ip, "53"))
			continue
		}
		if ip, ok := w.ipCache[fq]; ok {
			servers = append(servers, net.JoinHostPort(ip, "53"))
			continue
		}
		ips, e := net.LookupIP(strings.TrimSuffix(fq, "."))
		if e != nil {
			continue
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				addr := v4.String()
				w.ipCache[fq] = addr
				servers = append(servers, net.JoinHostPort(addr, "53"))
				break
			}
		}
	}
	return servers
}

func hasAnswer(msg *dns.Msg, qname string, qtype uint16) bool {
	if msg == nil {
		return false
	}
	fq := dns.Fqdn(qname)
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype && dns.Fqdn(rr.Header().Name) == fq {
			return true
		}
	}
	return false
}
