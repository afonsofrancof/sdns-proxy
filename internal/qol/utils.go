package qol

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func GenerateOutputPaths(outputDir, upstream string, dnssec, keepAlive bool) (csvPath, pcapPath string) {
	proto := DetectProtocol(upstream)
	serverName := ExtractServerName(upstream)
	cleanServer := cleanServerName(serverName)

	// Create date-based subdirectory
	date := time.Now().Format("2006-01-02")
	timestamp := time.Now().Format("150405") // HHMMSS for uniqueness

	// Organize hierarchically: resolver/date/filename
	subDir := filepath.Join(outputDir, cleanServer, date)

	// Create simple filename
	base := proto

	// Add flags if enabled
	var flags []string
	if dnssec {
		flags = append(flags, "dnssec")
	}
	if keepAlive {
		flags = append(flags, "persist")
	}

	if len(flags) > 0 {
		base = fmt.Sprintf("%s-%s", base, strings.Join(flags, "-"))
	}

	// Add timestamp
	filename := fmt.Sprintf("%s-%s", base, timestamp)

	return filepath.Join(subDir, filename+".csv"),
		filepath.Join(subDir, filename+".pcap")
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
	}

	// Clean the server name first
	cleaned := strings.ToLower(server)
	cleaned = strings.TrimPrefix(cleaned, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	cleaned = strings.Split(cleaned, "/")[0]
	cleaned = strings.Split(cleaned, ":")[0]

	// Check if we have a mapping
	if shortName, exists := serverMap[cleaned]; exists {
		return shortName
	}

	// For unknown servers, create a reasonable short name
	parts := strings.Split(cleaned, ".")
	if len(parts) >= 2 {
		// For domains like dns.example.com, take "example"
		if len(parts) >= 3 {
			return parts[len(parts)-2] // Second to last part
		}
		// For IPs or simple domains, take first part
		return parts[0]
	}

	return sanitizeShort(cleaned)
}

func sanitizeShort(s string) string {
	// Keep only alphanumeric and dash
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else if r == '.' || r == '_' || r == '-' {
			result.WriteRune('-')
		}
	}

	cleaned := result.String()
	// Remove consecutive dashes and trim
	for strings.Contains(cleaned, "--") {
		cleaned = strings.ReplaceAll(cleaned, "--", "-")
	}
	cleaned = strings.Trim(cleaned, "-")

	// Limit length
	if len(cleaned) > 15 {
		cleaned = cleaned[:15]
	}

	return cleaned
}

func DetectProtocol(upstream string) string {
	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err == nil && u.Scheme != "" {
			return strings.ToLower(u.Scheme)
		}
	}
	return "do53"
}

func ExtractServerName(upstream string) string {
	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err == nil {
			if u.Scheme == "https" && u.Path != "" && u.Path != "/" {
				return u.Host + u.Path
			}
			return u.Host
		}
	}
	return upstream
}
