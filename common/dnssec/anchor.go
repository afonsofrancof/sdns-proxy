package dnssec

import (
	"strings"

	"github.com/miekg/dns"
)

// rootAnchor is one IANA root zone trust anchor: a KSK key tag and the SHA-256
// digest of that key. A fetched root KSK is trusted if it matches any anchor.
type rootAnchor struct {
	keyTag uint16
	digest string // SHA-256, uppercase hex (matches DNSKEY.ToDS output)
}

// rootTrustAnchors holds the currently-valid root KSK trust anchors, as
// published by IANA (root-anchors.xml). Both the KSK-2017 and KSK-2024 keys
// are listed so validation keeps working across the KSK rollover, during which
// the root publishes and may sign with either key. The expired 2010 anchor
// (key tag 19036) is intentionally omitted.
var rootTrustAnchors = []rootAnchor{
	{keyTag: 20326, digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"}, // KSK-2017
	{keyTag: 38696, digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"}, // KSK-2024
}

const rootDigestType uint8 = dns.SHA256

// rootHints holds the IPv4 addresses of the DNS root servers, used to
// bootstrap iterative resolution in chain-of-trust (authoritative) mode.
var rootHints = []string{
	// Root servers. {a..m}.root-servers.net
	"198.41.0.4:53",
	"170.247.170.2:53",
	"192.33.4.12:53",
	"199.7.91.13:53",
	"192.203.230.10:53",
	"192.5.5.241:53",
	"192.112.36.4:53",
	"198.97.190.53:53",
	"192.36.148.17:53",
	"192.58.128.30:53",
	"193.0.14.129:53",
	"199.7.83.42:53",
	"202.12.27.33:53",
}

// matchesRootAnchor reports whether a root DNSKEY matches any trusted anchor,
// by key tag and SHA-256 digest.
func matchesRootAnchor(k *dns.DNSKEY) bool {
	tag := k.KeyTag()
	for _, a := range rootTrustAnchors {
		if tag != a.keyTag {
			continue
		}
		ds := k.ToDS(rootDigestType)
		if ds != nil && strings.EqualFold(ds.Digest, a.digest) {
			return true
		}
	}
	return false
}

// verifyRootAnchor confirms that a fetched root DNSKEY RRset contains a KSK
// matching one of the hardcoded trust anchors, and that the RRset is signed by
// a key in the set. On success the returned zone can validate child DS records.
func verifyRootAnchor(dnskeys *RRSet) (*SignedZone, error) {
	if dnskeys == nil || dnskeys.IsEmpty() || !dnskeys.IsSigned() {
		return nil, ErrDnskeyNotAvailable
	}

	zone := NewSignedZone(".")
	zone.DNSKey = dnskeys

	matched := false
	for _, rr := range dnskeys.RRs {
		k, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		zone.AddPubKey(k)
		if matchesRootAnchor(k) {
			matched = true
		}
	}

	if !matched {
		return nil, ErrDsInvalid
	}

	// The DNSKEY RRset must be signed by one of its own keys (the KSK).
	if err := zone.VerifyRRSIG(dnskeys); err != nil {
		return nil, err
	}
	return zone, nil
}
