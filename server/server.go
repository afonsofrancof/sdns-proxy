type Config struct {
	Address   string
	Upstream  string
	Fallback  string
	Bootstrap string
	DNSSEC    bool
	KeepAlive bool
	Timeout   time.Duration
	Verbose   bool
}

// Update the initClients method:
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
		DNSSEC:    s.config.DNSSEC,
		KeepAlive: s.config.KeepAlive,
	})
	if err != nil {
		logger.Error("Failed to create upstream client: %v", err)
		return fmt.Errorf("failed to create upstream client: %w", err)
	}
	s.upstreamClient = upstreamClient

	if s.config.Verbose {
		logger.Info("Initialized upstream client: %s -> %s (KeepAlive: %v)", s.config.Upstream, resolvedUpstream, s.config.KeepAlive)
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
			DNSSEC:    s.config.DNSSEC,
			KeepAlive: s.config.KeepAlive,
		})
		if err != nil {
			logger.Error("Failed to create fallback client: %v", err)
			return fmt.Errorf("failed to create fallback client: %w", err)
		}
		s.fallbackClient = fallbackClient

		if s.config.Verbose {
			logger.Info("Initialized fallback client: %s -> %s (KeepAlive: %v)", s.config.Fallback, resolvedFallback, s.config.KeepAlive)
		}
	}

	logger.Debug("All DNS clients initialized successfully")
	return nil
}
