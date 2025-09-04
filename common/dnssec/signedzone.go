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
	"log"
	"strings"

	"github.com/miekg/dns"
)

type SignedZone struct {
	Zone         string
	DNSKey       *RRSet
	DS           *RRSet
	ParentZone   *SignedZone
	PubKeyLookup map[uint16]*dns.DNSKEY
}

func NewSignedZone(domainName string) *SignedZone {
	return &SignedZone{
		Zone:         domainName,
		DS:           NewRRSet(),
		DNSKey:       NewRRSet(),
		PubKeyLookup: make(map[uint16]*dns.DNSKEY),
	}
}

func (z *SignedZone) LookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.PubKeyLookup[keyTag]
}

func (z *SignedZone) AddPubKey(k *dns.DNSKEY) {
	z.PubKeyLookup[k.KeyTag()] = k
}

func (z *SignedZone) HasDNSKeys() bool {
	return len(z.DNSKey.RRs) > 0
}

func (z *SignedZone) VerifyRRSIG(signedRRset *RRSet) error {
	if !signedRRset.IsSigned() {
		return ErrInvalidRRsig
	}

	key := z.LookupPubKey(signedRRset.RRSig.KeyTag)
	if key == nil {
		log.Printf("DNSKEY keytag %d not found in zone %s", signedRRset.RRSig.KeyTag, z.Zone)
		return ErrDnskeyNotAvailable
	}

	return signedRRset.ValidateSignature(key)
}

func (z *SignedZone) VerifyDS(dsRRset []dns.RR) error {
	log.Printf("Verifying DS for zone %s with %d DS records", z.Zone, len(dsRRset))
	for _, rr := range dsRRset {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}

		log.Printf("Checking DS keytag %d, digestType %d", ds.KeyTag, ds.DigestType)

		if ds.DigestType != dns.SHA256 {
			log.Printf("Unknown digest type (%d) on DS RR", ds.DigestType)
			continue
		}

		parentDsDigest := strings.ToUpper(ds.Digest)
		key := z.LookupPubKey(ds.KeyTag)
		if key == nil {
			log.Printf("DNSKEY keytag %d not found in zone %s", ds.KeyTag, z.Zone)
			return ErrDnskeyNotAvailable
		}

		dsDigest := strings.ToUpper(key.ToDS(ds.DigestType).Digest)
		log.Printf("Parent DS digest: %s, Computed digest: %s", parentDsDigest, dsDigest)
		if parentDsDigest == dsDigest {
			log.Printf("DS validation successful for keytag %d", ds.KeyTag)
			return nil
		}

		log.Printf("DS does not match DNSKEY for keytag %d", ds.KeyTag)
	}
	log.Printf("No matching DS found")
	return ErrDsInvalid
}
