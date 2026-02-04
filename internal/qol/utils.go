// ./internal/qol/utils.go
package qol

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

func GenerateOutputPaths(outputDir, upstream string, dnssec, authDNSSEC, keepAlive bool) (csvPath, pcapPath string) {
	proto := DetectProtocol(upstream)
	cleanServer := cleanServerName(upstream)

	subDir := filepath.Join(outputDir, cleanServer)

	base := proto
	var flags []string

	if dnssec {
		if authDNSSEC {
			flags = append(flags, "auth")
		} else {
			flags = append(flags, "trust")
		}
	}
	if keepAlive {
		flags = append(flags, "persist")
	}

	if len(flags) > 0 {
		base = fmt.Sprintf("%s-%s", base, strings.Join(flags, "-"))
	}

	return filepath.Join(subDir, base+".csv"),
		filepath.Join(subDir, base+".pcap")
}

func cleanServerName(server string) string {
	// Map common servers to readable names
	serverMap := map[string]string{
		"1.1.1.1":               "cloudflare",
		"1.0.0.1":               "cloudflare",
		"cloudflare-dns.com":    "cloudflare",
		"one.one.one.one":       "cloudflare",
		"8.8.8.8":               "google",
		"8.8.4.4":               "google",
		"dns.google":            "google",
		"dns.google.com":        "google",
		"9.9.9.9":               "quad9",
		"149.112.112.112":       "quad9",
		"dns.quad9.net":         "quad9",
		"dns10.quad9.net":       "quad9",
		"208.67.222.222":        "opendns",
		"208.67.220.220":        "opendns",
		"resolver1.opendns.com": "opendns",
		"94.140.14.14":          "adguard",
		"94.140.15.15":          "adguard",
		"dns.adguard.com":       "adguard",
		"dns.adguard-dns.com":   "adguard",
		"AQMAAAAAAAAAETk0LjE0MC4xNS4xNTo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20": "adguard",
	}

	serverName := ""
	cleanedUrl, err := url.Parse(server)
	if err != nil {
		serverName = server
	} else {
		serverName = cleanedUrl.Hostname()
	}

	// Check if we have a mapping
	if shortName, exists := serverMap[serverName]; exists {
		return shortName
	}

	return serverName
}

func DetectProtocol(upstream string) string {

	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err == nil && u.Scheme != "" {
			scheme := strings.ToLower(u.Scheme)
			// Normalize scheme names
			switch scheme {
			case "udp", "doudp":
				return "doudp"
			case "tcp", "dotcp":
				return "dotcp"
			case "tls", "dot":
				return "dot"
			case "https", "doh":
				return "doh"
			case "doh3":
				return "doh3"
			case "doq":
				return "doq"
			case "sdns":
				return "dnscrypt"
			default:
				return scheme
			}
		}
	}
	return "doudp"
}
