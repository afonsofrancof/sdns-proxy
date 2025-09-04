package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afonsofrancof/sdns-proxy/client"
	"github.com/miekg/dns"
)

type Config struct {
	Address   string
	Upstream  string
	Fallback  string
	Bootstrap string
	DNSSEC    bool
	Timeout   time.Duration
	Verbose   bool
}

type cacheKey struct {
	domain string
	qtype  uint16
}

type cacheEntry struct {
	records   []dns.RR
	expiresAt time.Time
}

type Server struct {
	config          Config
	upstreamClient  client.DNSClient
	fallbackClient  client.DNSClient
	bootstrapClient client.DNSClient
	resolvedHosts   map[string]string
	queryCache      map[cacheKey]*cacheEntry
	hostsMutex      sync.RWMutex
	cacheMutex      sync.RWMutex
	dnsServer       *dns.Server
}

func New(config Config) (*Server, error) {
	if config.Upstream == "" {
		return nil, fmt.Errorf("upstream server is required")
	}

	// Check if we need bootstrap server
	needsBootstrap := containsHostname(config.Upstream)
	if config.Fallback != "" {
		needsBootstrap = needsBootstrap || containsHostname(config.Fallback)
	}

	if needsBootstrap && config.Bootstrap == "" {
		return nil, fmt.Errorf("bootstrap server is required when upstream or fallback contains hostnames")
	}

	if config.Bootstrap != "" && containsHostname(config.Bootstrap) {
		return nil, fmt.Errorf("bootstrap server cannot contain hostnames: %s", config.Bootstrap)
	}

	s := &Server{
		config:        config,
		resolvedHosts: make(map[string]string),
		queryCache:    make(map[cacheKey]*cacheEntry),
	}

	// Create bootstrap client if needed
	if config.Bootstrap != "" {
		bootstrapClient, err := client.New(config.Bootstrap, client.Options{
			DNSSEC: false, // For now
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create bootstrap client: %w", err)
		}
		s.bootstrapClient = bootstrapClient
	}

	// Initialize upstream and fallback clients
	if err := s.initClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}

	// Setup DNS server
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSRequest)

	s.dnsServer = &dns.Server{
		Addr:    config.Address,
		Net:     "udp",
		Handler: mux,
	}

	return s, nil
}

func containsHostname(serverAddr string) bool {
	// Use the same parsing logic as the client package
	parsedURL, err := url.Parse(serverAddr)
	if err != nil {
		// If URL parsing fails, assume it's a plain address
		host, _, err := net.SplitHostPort(serverAddr)
		if err != nil {
			// Assume it's just a host
			return net.ParseIP(serverAddr) == nil
		}
		return net.ParseIP(host) == nil
	}

	host := parsedURL.Hostname()
	if host == "" {
		return false
	}

	return net.ParseIP(host) == nil
}

func (s *Server) initClients() error {
	// Initialize upstream client
	resolvedUpstream, err := s.resolveServerAddress(s.config.Upstream)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream %s: %w", s.config.Upstream, err)
	}

	upstreamClient, err := client.New(resolvedUpstream, client.Options{
		DNSSEC: s.config.DNSSEC,
	})
	if err != nil {
		return fmt.Errorf("failed to create upstream client: %w", err)
	}
	s.upstreamClient = upstreamClient

	if s.config.Verbose {
		log.Printf("Initialized upstream client: %s -> %s", s.config.Upstream, resolvedUpstream)
	}

	// Initialize fallback client if specified
	if s.config.Fallback != "" {
		resolvedFallback, err := s.resolveServerAddress(s.config.Fallback)
		if err != nil {
			return fmt.Errorf("failed to resolve fallback %s: %w", s.config.Fallback, err)
		}

		fallbackClient, err := client.New(resolvedFallback, client.Options{
			DNSSEC: s.config.DNSSEC,
		})
		if err != nil {
			return fmt.Errorf("failed to create fallback client: %w", err)
		}
		s.fallbackClient = fallbackClient

		if s.config.Verbose {
			log.Printf("Initialized fallback client: %s -> %s", s.config.Fallback, resolvedFallback)
		}
	}

	return nil
}

func (s *Server) resolveServerAddress(serverAddr string) (string, error) {
	// If it doesn't contain hostnames, return as-is
	if !containsHostname(serverAddr) {
		return serverAddr, nil
	}

	// If no bootstrap client, we can't resolve hostnames
	if s.bootstrapClient == nil {
		return "", fmt.Errorf("cannot resolve hostname in %s: no bootstrap server configured", serverAddr)
	}

	// Use the same parsing logic as the client package
	parsedURL, err := url.Parse(serverAddr)
	if err != nil {
		// Handle plain host:port format
		host, port, err := net.SplitHostPort(serverAddr)
		if err != nil {
			// Assume it's just a hostname
			resolvedIP, err := s.resolveHostname(serverAddr)
			if err != nil {
				return "", err
			}
			return resolvedIP, nil
		}

		resolvedIP, err := s.resolveHostname(host)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(resolvedIP, port), nil
	}

	// Handle URL format
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return "", fmt.Errorf("no hostname in URL: %s", serverAddr)
	}

	resolvedIP, err := s.resolveHostname(hostname)
	if err != nil {
		return "", err
	}

	// Replace hostname with IP in the URL
	port := parsedURL.Port()
	if port == "" {
		parsedURL.Host = resolvedIP
	} else {
		parsedURL.Host = net.JoinHostPort(resolvedIP, port)
	}

	return parsedURL.String(), nil
}

func (s *Server) resolveHostname(hostname string) (string, error) {
	// Check cache first
	s.hostsMutex.RLock()
	if ip, exists := s.resolvedHosts[hostname]; exists {
		s.hostsMutex.RUnlock()
		return ip, nil
	}
	s.hostsMutex.RUnlock()

	// Resolve using bootstrap
	if s.config.Verbose {
		log.Printf("Resolving hostname %s using bootstrap server", hostname)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.Id = dns.Id()
	msg.RecursionDesired = true

	msg, err := s.bootstrapClient.Query(msg)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s via bootstrap: %w", hostname, err)
	}

	if len(msg.Answer) == 0 {
		return "", fmt.Errorf("no A records found for %s", hostname)
	}

	// Find first A record
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ip := a.A.String()

			// Cache the result
			s.hostsMutex.Lock()
			s.resolvedHosts[hostname] = ip
			s.hostsMutex.Unlock()

			if s.config.Verbose {
				log.Printf("Resolved %s to %s", hostname, ip)
			}

			return ip, nil
		}
	}

	return "", fmt.Errorf("no valid A record found for %s", hostname)
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	question := r.Question[0]
	domain := strings.ToLower(question.Name)
	qtype := question.Qtype

	if s.config.Verbose {
		log.Printf("Query: %s %s from %s",
			question.Name,
			dns.TypeToString[qtype],
			w.RemoteAddr())
	}

	// Check cache first
	if cachedRecords := s.getCachedRecords(domain, qtype); cachedRecords != nil {
		response := s.buildResponse(r, cachedRecords)
		if s.config.Verbose {
			log.Printf("Cache hit: %s %s -> %d records",
				question.Name,
				dns.TypeToString[qtype],
				len(cachedRecords))
		}
		w.WriteMsg(response)
		return
	}

	// Try upstream first
	response, err := s.queryUpstream(s.upstreamClient, question.Name, qtype)
	if err != nil {
		if s.config.Verbose {
			log.Printf("Upstream query failed: %v", err)
		}

		// Try fallback if available
		if s.fallbackClient != nil {
			if s.config.Verbose {
				log.Printf("Trying fallback server")
			}

			response, err = s.queryUpstream(s.fallbackClient, question.Name, qtype)
			if err != nil {
				log.Printf("Both upstream and fallback failed for %s %s: %v",
					question.Name,
					dns.TypeToString[qtype],
					err)
			}
		}

		// If still failed, return SERVFAIL
		if err != nil {
			log.Printf("All servers failed for %s %s: %v",
				question.Name,
				dns.TypeToString[qtype],
				err)

			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return
		}
	}

	// Cache successful response
	s.cacheResponse(domain, qtype, response)

	// Copy request ID to response
	response.Id = r.Id

	if s.config.Verbose {
		log.Printf("Response: %s %s -> %d answers",
			question.Name,
			dns.TypeToString[qtype],
			len(response.Answer))
	}

	w.WriteMsg(response)
}

func (s *Server) getCachedRecords(domain string, qtype uint16) []dns.RR {
	key := cacheKey{domain: domain, qtype: qtype}

	s.cacheMutex.RLock()
	entry, exists := s.queryCache[key]
	s.cacheMutex.RUnlock()

	if !exists {
		return nil
	}

	// Check if expired and clean up on the spot
	if time.Now().After(entry.expiresAt) {
		s.cacheMutex.Lock()
		delete(s.queryCache, key)
		s.cacheMutex.Unlock()
		return nil
	}

	// Return a copy of the cached records
	records := make([]dns.RR, len(entry.records))
	for i, rr := range entry.records {
		records[i] = dns.Copy(rr)
	}
	return records
}

func (s *Server) buildResponse(request *dns.Msg, records []dns.RR) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)

	response.Answer = records

	return response
}

func (s *Server) cacheResponse(domain string, qtype uint16, msg *dns.Msg) {
	if msg == nil || len(msg.Answer) == 0 {
		return
	}

	var validRecords []dns.RR
	minTTL := uint32(3600)

	// Find minimum TTL from answer records
	for _, rr := range msg.Answer {
		// Only cache records that match our query type or are CNAMEs
		if rr.Header().Rrtype == qtype || rr.Header().Rrtype == dns.TypeCNAME {
			validRecords = append(validRecords, dns.Copy(rr))
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}

	if len(validRecords) == 0 {
		return
	}

	// Don't cache responses with very low TTL
	if minTTL < 10 {
		return
	}

	key := cacheKey{domain: domain, qtype: qtype}
	entry := &cacheEntry{
		records:   validRecords,
		expiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
	}

	s.cacheMutex.Lock()
	s.queryCache[key] = entry
	s.cacheMutex.Unlock()

	if s.config.Verbose {
		log.Printf("Cached %d records for %s %s (TTL: %ds)",
			len(validRecords), domain, dns.TypeToString[qtype], minTTL)
	}
}

func (s *Server) queryUpstream(upstreamClient client.DNSClient, domain string, qtype uint16) (*dns.Msg, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancel()

	// Channel to receive result
	type result struct {
		msg *dns.Msg
		err error
	}
	resultChan := make(chan result, 1)

	// Query in goroutine to respect context timeout
	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), qtype)
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		recvMsg, err := upstreamClient.Query(msg)
		resultChan <- result{msg: recvMsg, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.msg, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("upstream query timeout")
	}
}

func (s *Server) Start() error {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down DNS server...")
		s.Shutdown()
	}()

	log.Printf("DNS proxy server listening on %s", s.config.Address)
	return s.dnsServer.ListenAndServe()
}

func (s *Server) Shutdown() {
	if s.dnsServer != nil {
		s.dnsServer.Shutdown()
	}

	if s.upstreamClient != nil {
		s.upstreamClient.Close()
	}

	if s.fallbackClient != nil {
		s.fallbackClient.Close()
	}

	if s.bootstrapClient != nil {
		s.bootstrapClient.Close()
	}
}
