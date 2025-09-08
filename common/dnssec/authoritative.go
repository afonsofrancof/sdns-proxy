package dnssec

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/miekg/dns"
)

type AuthoritativeQuerier struct {
	client *dns.Client
	// Cache of NS records to avoid repeated lookups
	nsCache map[string][]string
	ipCache map[string]string
}

func NewAuthoritativeQuerier() *AuthoritativeQuerier {
	return &AuthoritativeQuerier{
		client: &dns.Client{
			Timeout: 10 * time.Second,
		},
		nsCache: make(map[string][]string),
		ipCache: make(map[string]string),
	}
}

func (aq *AuthoritativeQuerier) QueryAuthoritative(qname string, qtype uint16) (*dns.Msg, error) {
	logger.Debug("Querying authoritative servers for %s type %d", qname, qtype)

	var zone string
	if qtype == dns.TypeDS {
		zone = aq.getParentZone(qname)
		if zone == "" {
			logger.Debug("No parent zone for %s - returning NXDOMAIN for DS query", qname)
			msg := &dns.Msg{}
			msg.SetRcode(&dns.Msg{}, dns.RcodeNameError)
			return msg, nil
		}
	} else {
		zone = aq.findZone(qname)
	}

	logger.Debug("Determined zone: %s for query %s type %d", zone, qname, qtype)

	// Get NS names (not IPs yet)
	nsNames, err := aq.findAuthoritativeNSNames(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to find authoritative servers: %w", err)
	}

	// Try servers one by one, resolving IPs lazily
	var lastErr error
	for _, nsName := range nsNames {
		server := aq.resolveNSToIP(nsName)
		if server == "" {
			continue
		}

		logger.Debug("Trying server: %s (%s)", server, nsName)
		msg, err := aq.queryServer(server, qname, qtype)
		if err != nil {
			logger.Debug("Server %s failed: %v", server, err)
			lastErr = err
			continue
		}

		logger.Debug("Server %s responded, authoritative: %v, rcode: %d, answers: %d", server, msg.Authoritative, msg.Rcode, len(msg.Answer))
		if (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0) || msg.Rcode == dns.RcodeNameError {
			return msg, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all servers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no authoritative response received")
}

func (aq *AuthoritativeQuerier) findAuthoritativeNSNames(zone string) ([]string, error) {

	if nsNames, exists := aq.nsCache[zone]; exists {
		logger.Debug("Using cached NS names for %s: %v", zone, nsNames)
		return nsNames, nil
	}

	logger.Debug("Looking for NS records for zone: %s", zone)

	// Use a public resolver to find the NS records
	resolver := &dns.Client{Timeout: 5 * time.Second}

	msg, _, err := resolver.Exchange(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{Name: dns.Fqdn(zone), Qtype: dns.TypeNS, Qclass: dns.ClassINET}},
	}, "8.8.8.8:53")

	if err != nil {
		return nil, fmt.Errorf("failed to query NS records: %w", err)
	}

	var nsNames []string

	// Collect NS records from answer section
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}

	// Also check authority section if answer is empty
	if len(nsNames) == 0 {
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}
	}

	if len(nsNames) == 0 {
		return nil, fmt.Errorf("no NS servers found for %s", zone)
	}

	logger.Debug("Found NS names for %s: %v", zone, nsNames)
	aq.nsCache[zone] = nsNames
	logger.Debug("Cached NS names for %s: %v", zone, nsNames)
	return nsNames, nil
}

func (aq *AuthoritativeQuerier) getParentZone(qname string) string {
	logger.Debug("Getting parent zone for: %s", qname)

	// Clean the qname
	qname = strings.TrimSuffix(qname, ".")

	// Root zone has no parent
	if qname == "" || qname == "." {
		logger.Debug("Root zone has no parent")
		return ""
	}

	labels := dns.SplitDomainName(qname)
	logger.Debug("Labels for %s: %v", qname, labels)

	if len(labels) <= 1 {
		logger.Debug("Parent of TLD %s is root", qname)
		return "." // Parent of TLD is root
	}

	parentLabels := labels[1:]
	parent := dns.Fqdn(strings.Join(parentLabels, "."))
	logger.Debug("Parent zone of %s is %s", qname, parent)
	return parent
}

func (aq *AuthoritativeQuerier) findZone(qname string) string {
	// For now, assume the zone is the domain itself
	// In a more sophisticated implementation, you'd walk up the hierarchy
	labels := dns.SplitDomainName(qname)
	if len(labels) >= 2 {
		return labels[len(labels)-2] + "." + labels[len(labels)-1] + "."
	}
	return qname
}

func (aq *AuthoritativeQuerier) resolveNSToIP(nsName string) string {
	if ip, exists := aq.ipCache[nsName]; exists {
		logger.Debug("Using cached IP for %s: %s", nsName, ip)
		return ip
	}

	nsName = strings.TrimSuffix(nsName, ".")
	logger.Debug("Resolving NS %s to IP", nsName)

	ips, err := net.LookupIP(nsName)
	if err != nil {
		logger.Debug("Failed to resolve %s: %v", nsName, err)
		return ""
	}

	for _, ip := range ips {
		if ip.To4() != nil { // Prefer IPv4
			result := ip.String() + ":53"
			logger.Debug("Resolved %s to %s", nsName, result)

			// Cache the result before returning
			aq.ipCache[nsName] = result
			return result
		}
	}

	return ""
}

func (aq *AuthoritativeQuerier) queryServer(server, qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.SetEdns0(4096, true) // Enable DNSSEC

	logger.Debug("Querying %s for %s type %d", server, qname, qtype)
	msg, _, err := aq.client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	logger.Debug("Response from %s: rcode=%d, answers=%d", server, msg.Rcode, len(msg.Answer))
	return msg, err
}
