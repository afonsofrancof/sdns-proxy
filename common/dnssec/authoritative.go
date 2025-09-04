package dnssec

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

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
	log.Printf("Querying authoritative servers for %s type %d", qname, qtype)

	var zone string
	if qtype == dns.TypeDS {
		zone = aq.getParentZone(qname)
		if zone == "" {
			log.Printf("No parent zone for %s - returning NXDOMAIN for DS query", qname)
			msg := &dns.Msg{}
			msg.SetRcode(&dns.Msg{}, dns.RcodeNameError)
			return msg, nil
		}
	} else {
		zone = aq.findZone(qname)
	}

	log.Printf("Determined zone: %s for query %s type %d", zone, qname, qtype)

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

		log.Printf("Trying server: %s (%s)", server, nsName)
		msg, err := aq.queryServer(server, qname, qtype)
		if err != nil {
			log.Printf("Server %s failed: %v", server, err)
			lastErr = err
			continue
		}

		log.Printf("Server %s responded, authoritative: %v, rcode: %d, answers: %d", server, msg.Authoritative, msg.Rcode, len(msg.Answer))
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
		log.Printf("Using cached NS names for %s: %v", zone, nsNames)
		return nsNames, nil
	}

	log.Printf("Looking for NS records for zone: %s", zone)

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

	log.Printf("Found NS names for %s: %v", zone, nsNames)
	aq.nsCache[zone] = nsNames
	log.Printf("Cached NS names for %s: %v", zone, nsNames)
	return nsNames, nil
}

func (aq *AuthoritativeQuerier) getParentZone(qname string) string {
	log.Printf("Getting parent zone for: %s", qname)

	// Clean the qname
	qname = strings.TrimSuffix(qname, ".")

	// Root zone has no parent
	if qname == "" || qname == "." {
		log.Printf("Root zone has no parent")
		return ""
	}

	labels := dns.SplitDomainName(qname)
	log.Printf("Labels for %s: %v", qname, labels)

	if len(labels) <= 1 {
		log.Printf("Parent of TLD %s is root", qname)
		return "." // Parent of TLD is root
	}

	parentLabels := labels[1:]
	parent := dns.Fqdn(strings.Join(parentLabels, "."))
	log.Printf("Parent zone of %s is %s", qname, parent)
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
		log.Printf("Using cached IP for %s: %s", nsName, ip)
		return ip
	}

	nsName = strings.TrimSuffix(nsName, ".")
	log.Printf("Resolving NS %s to IP", nsName)

	ips, err := net.LookupIP(nsName)
	if err != nil {
		log.Printf("Failed to resolve %s: %v", nsName, err)
		return ""
	}

	for _, ip := range ips {
		if ip.To4() != nil { // Prefer IPv4
			result := ip.String() + ":53"
			log.Printf("Resolved %s to %s", nsName, result)
			
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

	log.Printf("Querying %s for %s type %d", server, qname, qtype)
	msg, _, err := aq.client.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	log.Printf("Response from %s: rcode=%d, answers=%d", server, msg.Rcode, len(msg.Answer))
	return msg, err
}
