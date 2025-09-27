package qol

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func GenerateOutputPaths(outputDir, upstream string, dnssec, keepAlive bool) (jsonPath, pcapPath string) {
	proto := DetectProtocol(upstream)
	serverName := ExtractServerName(upstream)
	ts := time.Now().Format("20060102_1504")
	dnssecStr := map[bool]string{true: "on", false: "off"}[dnssec]
	keepAliveStr := map[bool]string{true: "on", false: "off"}[keepAlive]

	base := fmt.Sprintf("%s_%s_dnssec_%s_keepalive_%s_%s",
		proto, sanitize(serverName), dnssecStr, keepAliveStr, ts)

	return filepath.Join(outputDir, base+".jsonl"),
		filepath.Join(outputDir, base+".pcap")
}

func sanitize(s string) string {
	return strings.NewReplacer(":", "_", "/", "_", ".", "_").Replace(s)
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
