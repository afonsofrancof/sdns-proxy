package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afonsofrancof/sdns-proxy/client"
	"github.com/afonsofrancof/sdns-proxy/common/logger"
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
	logger.Debug("Creating new server with config: %+v", config)

	if config.Upstream == "" {
		logger.Error("Upstream server is required")
		return nil, fmt.Errorf("upstream server is required")
	}

	// Check if we need bootstrap server
	needsBootstrap := containsHostname(config.Upstream)
	if config.Fallback != "" {
		needsBootstrap = needsBootstrap || containsHostname(config.Fallback)
	}

	logger.Debug("Bootstrap needed: %v (upstream has hostname: %v, fallback has hostname: %v)",
		needsBootstrap, containsHostname(config.Upstream),
		config.Fallback != "" && containsHostname(config.Fallback))

	if needsBootstrap && config.Bootstrap == "" {
		logger.Error("Bootstrap server is required when upstream or fallback contains hostnames")
		return nil, fmt.Errorf("bootstrap server is required when upstream or fallback contains hostnames")
	}

	if config.Bootstrap != "" && containsHostname(config.Bootstrap) {
		logger.Error("Bootstrap server cannot contain hostnames: %s", config.Bootstrap)
		return nil, fmt.Errorf("bootstrap server cannot contain hostnames: %s", config.Bootstrap)
	}

	s := &Server{
		config:        config,
		resolvedHosts: make(map[string]string),
		queryCache:    make(map[cacheKey]*cacheEntry),
	}

	// Create bootstrap client if needed
	if config.Bootstrap != "" {
		logger.Debug("Creating bootstrap client for %s", config.Bootstrap)
		bootstrapClient, err := client.New(config.Bootstrap, client.Options{
			DNSSEC: false,
		})
		if err != nil {
			logger.Error("Failed to create bootstrap client: %v", err)
			return nil, fmt.Errorf("failed to create bootstrap client: %w", err)
		}
		s.bootstrapClient = bootstrapClient
		logger.Debug("Bootstrap client created successfully")
	}

	// Initialize upstream and fallback clients
	if err := s.initClients(); err != nil {
		logger.Error("Failed to initialize clients: %v", err)
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

	logger.Debug("Server created successfully, listening on %s", config.Address)
	return s, nil
}

func containsHostname(serverAddr string) bool {
	logger.Debug("Checking if %s contains hostname", serverAddr)

	// Use the same parsing logic as the client package
	parsedURL, err := url.Parse(serverAddr)
	if err != nil {
		logger.Debug("URL parsing failed for %s, treating as plain address", serverAddr)
		// If URL parsing fails, assume it's a plain address
		host, _, err := net.SplitHostPort(serverAddr)
		if err != nil {
			// Assume it's just a host
			isHostname := net.ParseIP(serverAddr) == nil
			logger.Debug("Address %s is hostname: %v", serverAddr, isHostname)
			return isHostname
		}
		isHostname := net.ParseIP(host) == nil
		logger.Debug("Host %s from %s is hostname: %v", host, serverAddr, isHostname)
		return isHostname
	}

	host := parsedURL.Hostname()
	if host == "" {
		logger.Debug("No hostname found in URL %s", serverAddr)
		return false
	}

	isHostname := net.ParseIP(host) == nil
	logger.Debug("Host %s from URL %s is hostname: %v", host, serverAddr, isHostname)
	return isHostname
}

func (s *Server) initClients() error {
	logger.Debug("Initializing DNS clients")

	// Initialize upstream client
	resolvedUpstream, err := s.resolveServerAddress(s.config.Upstream)
	if err != nil {
		logger.Error("Failed to resolve upstream %s: %v", s.config.Upstream, err)
		return fmt.Errorf("failed to resolve upstream %s: %w", s.config.Upstream, err)
	}

	logger.Debug("Creating upstream client for %s (resolved: %s)", s.config.Upstream, resolvedUpstream)
	upstreamClient, err := client.New(resolvedUpstream, client.Options{
		DNSSEC: s.config.DNSSEC,
	})
	if err != nil {
		logger.Error("Failed to create upstream client: %v", err)
		return fmt.Errorf("failed to create upstream client: %w", err)
	}
	s.upstreamClient = upstreamClient

	if s.config.Verbose {
		logger.Info("Initialized upstream client: %s -> %s", s.config.Upstream, resolvedUpstream)
	}

	// Initialize fallback client if specified
	if s.config.Fallback != "" {
		resolvedFallback, err := s.resolveServerAddress(s.config.Fallback)
		if err != nil {
			logger.Error("Failed to resolve fallback %s: %v", s.config.Fallback, err)
			return fmt.Errorf("failed to resolve fallback %s: %w", s.config.Fallback, err)
		}

		logger.Debug("Creating fallback client for %s (resolved: %s)", s.config.Fallback, resolvedFallback)
		fallbackClient, err := client.New(resolvedFallback, client.Options{
			DNSSEC: s.config.DNSSEC,
		})
		if err != nil {
			logger.Error("Failed to create fallback client: %v", err)
			return fmt.Errorf("failed to create fallback client: %w", err)
		}
		s.fallbackClient = fallbackClient

		if s.config.Verbose {
			logger.Info("Initialized fallback client: %s -> %s", s.config.Fallback, resolvedFallback)
		}
	}

	logger.Debug("All DNS clients initialized successfully")
	return nil
}

func (s *Server) resolveServerAddress(serverAddr string) (string, error) {
	logger.Debug("Resolving server address: %s", serverAddr)

	// If it doesn't contain hostnames, return as-is
	if !containsHostname(serverAddr) {
		logger.Debug("Address %s contains no hostnames, returning as-is", serverAddr)
		return serverAddr, nil
	}

	// If no bootstrap client, we can't resolve hostnames
	if s.bootstrapClient == nil {
		logger.Error("Cannot resolve hostname in %s: no bootstrap server configured", serverAddr)
		return "", fmt.Errorf("cannot resolve hostname in %s: no bootstrap server configured", serverAddr)
	}

	// Use the same parsing logic as the client package
	parsedURL, err := url.Parse(serverAddr)
	if err != nil {
		logger.Debug("Parsing %s as plain host:port format", serverAddr)
		// Handle plain host:port format
		host, port, err := net.SplitHostPort(serverAddr)
		if err != nil {
			// Assume it's just a hostname
			resolvedIP, err := s.resolveHostname(serverAddr)
			if err != nil {
				return "", err
			}
			logger.Debug("Resolved %s to %s", serverAddr, resolvedIP)
			return resolvedIP, nil
		}

		resolvedIP, err := s.resolveHostname(host)
		if err != nil {
			return "", err
		}
		resolved := net.JoinHostPort(resolvedIP, port)
		logger.Debug("Resolved %s to %s", serverAddr, resolved)
		return resolved, nil
	}

	// Handle URL format
	hostname := parsedURL.Hostname()
	if hostname == "" {
		logger.Error("No hostname in URL: %s", serverAddr)
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

	resolved := parsedURL.String()
	logger.Debug("Resolved URL %s to %s", serverAddr, resolved)
	return resolved, nil
}

func (s *Server) resolveHostname(hostname string) (string, error) {
	logger.Debug("Resolving hostname: %s", hostname)

	// Check cache first
	s.hostsMutex.RLock()
	if ip, exists := s.resolvedHosts[hostname]; exists {
		s.hostsMutex.RUnlock()
		logger.Debug("Found cached resolution for %s: %s", hostname, ip)
		return ip, nil
	}
	s.hostsMutex.RUnlock()

	// Resolve using bootstrap
	if s.config.Verbose {
		logger.Info("Resolving hostname %s using bootstrap server", hostname)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.Id = dns.Id()
	msg.RecursionDesired = true

	logger.Debug("Sending bootstrap query for %s (ID: %d)", hostname, msg.Id)
	msg, err := s.bootstrapClient.Query(msg)
	if err != nil {
		logger.Error("Bootstrap query failed for %s: %v", hostname, err)
		return "", fmt.Errorf("failed to resolve %s via bootstrap: %w", hostname, err)
	}

	logger.Debug("Bootstrap response for %s: %d answers", hostname, len(msg.Answer))
	if len(msg.Answer) == 0 {
		logger.Error("No A records found for %s", hostname)
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
				logger.Info("Resolved %s to %s", hostname, ip)
			}
			logger.Debug("Cached resolution: %s -> %s", hostname, ip)

			return ip, nil
		}
	}

	logger.Error("No valid A record found for %s", hostname)
	return "", fmt.Errorf("no valid A record found for %s", hostname)
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		logger.Debug("Received request with no questions from %s", w.RemoteAddr())
		dns.HandleFailed(w, r)
		return
	}

	question := r.Question[0]
	domain := strings.ToLower(question.Name)
	qtype := question.Qtype

	logger.Debug("Handling DNS request: %s %s from %s (ID: %d)",
		question.Name, dns.TypeToString[qtype], w.RemoteAddr(), r.Id)

	if s.config.Verbose {
		logger.Info("Query: %s %s from %s",
			question.Name,
			dns.TypeToString[qtype],
			w.RemoteAddr())
	}

	// Check cache first
	if cachedRecords := s.getCachedRecords(domain, qtype); cachedRecords != nil {
		response := s.buildResponse(r, cachedRecords)
		if s.config.Verbose {
			logger.Info("Cache hit: %s %s -> %d records",
				question.Name,
				dns.TypeToString[qtype],
				len(cachedRecords))
		}
		logger.Debug("Serving cached response for %s %s (%d records)",
			question.Name, dns.TypeToString[qtype], len(cachedRecords))
		w.WriteMsg(response)
		return
	}

	logger.Debug("Cache miss for %s %s, querying upstream", question.Name, dns.TypeToString[qtype])

	// Try upstream first
	response, err := s.queryUpstream(s.upstreamClient, question.Name, qtype)
	if err != nil {
		if s.config.Verbose {
			logger.Info("Upstream query failed: %v", err)
		}
		logger.Debug("Upstream query failed for %s %s: %v", question.Name, dns.TypeToString[qtype], err)

		// Try fallback if available
		if s.fallbackClient != nil {
			if s.config.Verbose {
				logger.Info("Trying fallback server")
			}
			logger.Debug("Attempting fallback query for %s %s", question.Name, dns.TypeToString[qtype])

			response, err = s.queryUpstream(s.fallbackClient, question.Name, qtype)
			if err != nil {
				logger.Error("Both upstream and fallback failed for %s %s: %v",
					question.Name,
					dns.TypeToString[qtype],
					err)
			} else {
				logger.Debug("Fallback query succeeded for %s %s", question.Name, dns.TypeToString[qtype])
			}
		}

		// If still failed, return SERVFAIL
		if err != nil {
			logger.Error("All servers failed for %s %s: %v",
				question.Name,
				dns.TypeToString[qtype],
				err)

			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return
		}
	} else {
		logger.Debug("Upstream query succeeded for %s %s", question.Name, dns.TypeToString[qtype])
	}

	// Cache successful response
	s.cacheResponse(domain, qtype, response)

	// Copy request ID to response
	response.Id = r.Id

	if s.config.Verbose {
		logger.Info("Response: %s %s -> %d answers",
			question.Name,
			dns.TypeToString[qtype],
			len(response.Answer))
	}

	logger.Debug("Sending response for %s %s: %d answers, rcode: %s",
		question.Name, dns.TypeToString[qtype], len(response.Answer), dns.RcodeToString[response.Rcode])
	w.WriteMsg(response)
}

func (s *Server) getCachedRecords(domain string, qtype uint16) []dns.RR {
	key := cacheKey{domain: domain, qtype: qtype}

	s.cacheMutex.RLock()
	entry, exists := s.queryCache[key]
	s.cacheMutex.RUnlock()

	if !exists {
		logger.Debug("No cache entry for %s %s", domain, dns.TypeToString[qtype])
		return nil
	}

	// Check if expired and clean up on the spot
	if time.Now().After(entry.expiresAt) {
		logger.Debug("Cache entry expired for %s %s", domain, dns.TypeToString[qtype])
		s.cacheMutex.Lock()
		delete(s.queryCache, key)
		s.cacheMutex.Unlock()
		return nil
	}

	logger.Debug("Cache hit for %s %s (%d records, expires in %v)",
		domain, dns.TypeToString[qtype], len(entry.records), time.Until(entry.expiresAt))

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
	logger.Debug("Built response with %d records", len(records))
	return response
}

func (s *Server) cacheResponse(domain string, qtype uint16, msg *dns.Msg) {
	if msg == nil || len(msg.Answer) == 0 {
		logger.Debug("Not caching empty response for %s %s", domain, dns.TypeToString[qtype])
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
		logger.Debug("No valid records to cache for %s %s", domain, dns.TypeToString[qtype])
		return
	}

	// Don't cache responses with very low TTL
	if minTTL < 10 {
		logger.Debug("TTL too low (%ds) for caching %s %s", minTTL, domain, dns.TypeToString[qtype])
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
		logger.Info("Cached %d records for %s %s (TTL: %ds)",
			len(validRecords), domain, dns.TypeToString[qtype], minTTL)
	}
	logger.Debug("Cached %d records for %s %s (TTL: %ds, expires: %v)",
		len(validRecords), domain, dns.TypeToString[qtype], minTTL, entry.expiresAt)
}

func (s *Server) queryUpstream(upstreamClient client.DNSClient, domain string, qtype uint16) (*dns.Msg, error) {
	logger.Debug("Querying upstream for %s %s", domain, dns.TypeToString[qtype])

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

		logger.Debug("Sending upstream query: %s %s (ID: %d)", domain, dns.TypeToString[qtype], msg.Id)
		recvMsg, err := upstreamClient.Query(msg)
		if err != nil {
			logger.Debug("Upstream query error for %s %s: %v", domain, dns.TypeToString[qtype], err)
		} else {
			logger.Debug("Upstream query response for %s %s: %d answers, rcode: %s",
				domain, dns.TypeToString[qtype], len(recvMsg.Answer), dns.RcodeToString[recvMsg.Rcode])
		}
		resultChan <- result{msg: recvMsg, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.msg, res.err
	case <-ctx.Done():
		logger.Debug("Upstream query timeout for %s %s after %v", domain, dns.TypeToString[qtype], s.config.Timeout)
		return nil, fmt.Errorf("upstream query timeout")
	}
}

func (s *Server) Start() error {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan
		logger.Info("Received signal %v, shutting down DNS server...", sig)
		s.Shutdown()
	}()

	logger.Info("DNS proxy server listening on %s", s.config.Address)
	logger.Debug("Server starting with timeout: %v, DNSSEC: %v", s.config.Timeout, s.config.DNSSEC)
	return s.dnsServer.ListenAndServe()
}

func (s *Server) Shutdown() {
	logger.Debug("Shutting down server components")

	if s.dnsServer != nil {
		logger.Debug("Shutting down DNS server")
		s.dnsServer.Shutdown()
	}

	if s.upstreamClient != nil {
		logger.Debug("Closing upstream client")
		s.upstreamClient.Close()
	}

	if s.fallbackClient != nil {
		logger.Debug("Closing fallback client")
		s.fallbackClient.Close()
	}

	if s.bootstrapClient != nil {
		logger.Debug("Closing bootstrap client")
		s.bootstrapClient.Close()
	}

	logger.Info("Server shutdown complete")
}
