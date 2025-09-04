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

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

type AuthenticationChain struct {
	DelegationChain []SignedZone
}

func NewAuthenticationChain() *AuthenticationChain {
	return &AuthenticationChain{}
}

func (ac *AuthenticationChain) Populate(domainName string, queryFunc func(string, uint16) (*dns.Msg, error)) error {
	// Clean domain name and split into components
	domainName = strings.TrimSuffix(domainName, ".")
	qnameComponents := strings.Split(domainName, ".")

	// Remove empty components
	var cleanComponents []string
	for _, comp := range qnameComponents {
		if comp != "" {
			cleanComponents = append(cleanComponents, comp)
		}
	}

	// Build zones from root down to target
	// For example.com: [".","com.","example.com."]
	zones := []string{"."} // Start with root

	// Add each level from TLD down to target
	for i := len(cleanComponents) - 1; i >= 0; i-- {
		zone := dns.Fqdn(strings.Join(cleanComponents[i:], "."))
		zones = append(zones, zone)
	}

	log.Printf("Building DNSSEC chain for zones: %v", zones)

	ac.DelegationChain = make([]SignedZone, 0, len(zones))

	// Query each zone from root down
	for i, zoneName := range zones {
		log.Printf("Querying zone: %s", zoneName)

		delegation, err := ac.queryDelegation(zoneName, queryFunc)
		if err != nil {
			return fmt.Errorf("failed to query zone %s: %w", zoneName, err)
		}

		// Set parent relationship (previous zone in chain is parent)
		if i > 0 {
			delegation.ParentZone = &ac.DelegationChain[i-1]
		}

		ac.DelegationChain = append(ac.DelegationChain, *delegation)
	}

	return nil
}

func (ac *AuthenticationChain) queryDelegation(domainName string, queryFunc func(string, uint16) (*dns.Msg, error)) (*SignedZone, error) {
	signedZone := NewSignedZone(domainName)

	// Query DNSKEY records
	dnskeyRRset, err := ac.queryRRset(domainName, dns.TypeDNSKEY, queryFunc)
	if err != nil {
		return nil, err
	}
	signedZone.DNSKey = dnskeyRRset

	log.Printf("Found %d DNSKEY records for %s", len(dnskeyRRset.RRs), domainName)

	// Populate public key lookup
	for _, rr := range signedZone.DNSKey.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			signedZone.AddPubKey(dnskey)
			log.Printf("Added DNSKEY for %s: keytag=%d, flags=%d, algorithm=%d", domainName, dnskey.KeyTag(), dnskey.Flags, dnskey.Algorithm)
		}
	}

	// Only query DS records for non-root zones
	if domainName != "." {
		dsRRset, _ := ac.queryRRset(domainName, dns.TypeDS, queryFunc)
		signedZone.DS = dsRRset
		if dsRRset != nil && len(dsRRset.RRs) > 0 {
			log.Printf("Found %d DS records for %s", len(dsRRset.RRs), domainName)
			for _, rr := range dsRRset.RRs {
				if ds, ok := rr.(*dns.DS); ok {
					log.Printf("DS record for %s: keytag=%d", domainName, ds.KeyTag)
				}
			}
		}
	} else {
		// Root zone has no DS records - trusted by default
		signedZone.DS = NewRRSet()
		log.Printf("Root zone - no DS records, trusted by default")
	}

	return signedZone, nil
}

func (ac *AuthenticationChain) queryRRset(qname string, qtype uint16, queryFunc func(string, uint16) (*dns.Msg, error)) (*RRSet, error) {
	r, err := queryFunc(qname, qtype)
	if err != nil {
		log.Printf("cannot lookup %v", err)
		return NewRRSet(), nil // Return empty RRSet instead of nil
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s", qname)
		return NewRRSet(), nil // Return empty RRSet instead of nil
	}

	result := NewRRSet()
	if r.Answer == nil {
		return result, nil
	}

	result.RRs = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			if result.RRSig == nil || t.TypeCovered == qtype {
				result.RRSig = t
			}
		default:
			if rr != nil && rr.Header().Rrtype == qtype {
				result.RRs = append(result.RRs, rr)
			}
		}
	}
	return result, nil
}

func (ac *AuthenticationChain) Verify(answerRRset *RRSet) error {
	if len(ac.DelegationChain) == 0 {
		return ErrDnskeyNotAvailable
	}

	// Find the target zone (last in chain)
	targetZone := &ac.DelegationChain[len(ac.DelegationChain)-1]

	// Verify the answer RRset against target zone's keys
	err := targetZone.VerifyRRSIG(answerRRset)
	if err != nil {
		log.Printf("Answer RRSIG verification failed: %v", err)
		return ErrInvalidRRsig
	}

	// Validate the chain from root down
	for _, zone := range ac.DelegationChain {
		log.Printf("Validating zone: %s", zone.Zone)

		// Verify DNSKEY RRset signature
		if !zone.HasDNSKeys() {
			log.Printf("No DNSKEYs for zone %s", zone.Zone)
			return ErrDnskeyNotAvailable
		}

		err := zone.VerifyRRSIG(zone.DNSKey)
		if err != nil {
			log.Printf("DNSKEY validation failed for %s: %v", zone.Zone, err)
			return ErrRrsigValidationError
		}

		// Skip ALL validation for root - just trust it
		if zone.Zone == "." {
			log.Printf("Root zone - trusted by default, no validation performed")
			continue
		}

		// For non-root zones, validate DS records against parent zone
		if zone.ParentZone == nil {
			log.Printf("Non-root zone %s has no parent", zone.Zone)
			return fmt.Errorf("non-root zone %s has no parent", zone.Zone)
		}

		if zone.DS == nil || zone.DS.IsEmpty() {
			log.Printf("No DS records for zone %s", zone.Zone)
			return ErrDsNotAvailable
		}

		// Verify DS signature using parent's key
		err = zone.ParentZone.VerifyRRSIG(zone.DS)
		if err != nil {
			log.Printf("DS signature validation failed for %s: %v", zone.Zone, err)
			return ErrRrsigValidationError
		}

		// Verify DS matches this zone's DNSKEY
		err = zone.VerifyDS(zone.DS.RRs)
		if err != nil {
			log.Printf("DS-DNSKEY validation failed for %s: %v", zone.Zone, err)
			return ErrDsInvalid
		}

		log.Printf("Zone %s validated successfully", zone.Zone)
	}

	log.Printf("DNSSEC validation successful for entire chain!")
	return nil
}
