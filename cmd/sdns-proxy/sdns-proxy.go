package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/afonsofrancof/sdns-proxy/client"
	"github.com/afonsofrancof/sdns-proxy/common/logger"
	"github.com/afonsofrancof/sdns-proxy/server"

	"github.com/alecthomas/kong"
	"github.com/miekg/dns"
)

var cli struct {
	Debug  bool      `help:"Enable debug logging globally." short:"D" env:"DEBUG"`
	Query  QueryCmd  `cmd:"" help:"Perform a DNS query (client mode)."`
	Listen ListenCmd `cmd:"" help:"Run as a DNS listener/resolver (server mode)."`
}

type QueryCmd struct {
	DomainName          string        `help:"Domain name to resolve." arg:"" required:""`
	Server              string        `help:"Upstream server address (e.g., https://1.1.1.1/dns-query, tls://1.1.1.1, 8.8.8.8)." short:"s" required:""`
	QueryType           string        `help:"Query type (A, AAAA, MX, TXT, etc.)." short:"t" enum:"A,AAAA,MX,TXT,NS,CNAME,SOA,PTR,DNSKEY" default:"A"`
	DNSSEC              bool          `help:"Enable DNSSEC (DO bit)." short:"d"`
	AuthoritativeDNSSEC bool          `help:"Use authoritative DNSSEC validation instead of trusting resolver." short:"a"`
	ValidateOnly        bool          `help:"Only return DNSSEC validated responses." short:"V"`
	StrictValidation    bool          `help:"Fail on any DNSSEC validation error." short:"S"`
	KeepAlive           bool          `help:"Use persistent connections." short:"k"`
	Timeout             time.Duration `help:"Timeout for the query operation." default:"10s"`
	KeyLogFile          string        `help:"Path to TLS key log file (for DoT/DoH/DoQ)." env:"SSLKEYLOGFILE"`
}

type ListenCmd struct {
	Address             string        `help:"Address to listen on (e.g., :53, :8053)." default:":53"`
	Upstream            string        `help:"Upstream DNS server (e.g., https://1.1.1.1/dns-query, tls://8.8.8.8)." short:"u" required:""`
	Fallback            string        `help:"Fallback DNS server (e.g., https://1.1.1.1/dns-query, tls://8.8.8.8)." short:"f"`
	Bootstrap           string        `help:"Bootstrap DNS server (must be an IP address, e.g., 8.8.8.8, 1.1.1.1)." short:"b"`
	DNSSEC              bool          `help:"Enable DNSSEC for upstream queries." short:"d"`
	AuthoritativeDNSSEC bool          `help:"Use authoritative DNSSEC validation instead of trusting resolver." short:"a"`
	KeepAlive           bool          `help:"Use persistent connections to upstream servers." short:"k"`
	Timeout             time.Duration `help:"Timeout for upstream queries." default:"5s"`
	Verbose             bool          `help:"Enable verbose logging." short:"v"`
}

func (q *QueryCmd) Run() error {
	logger.Info("Querying %s for %s type %s (DNSSEC: %v, AuthoritativeDNSSEC: %v, ValidateOnly: %v, StrictValidation: %v, KeepAlive: %v, Timeout: %v)",
		q.Server, q.DomainName, q.QueryType, q.DNSSEC, q.AuthoritativeDNSSEC, q.ValidateOnly, q.StrictValidation, q.KeepAlive, q.Timeout)

	opts := client.Options{
		DNSSEC:              q.DNSSEC,
		AuthoritativeDNSSEC: q.AuthoritativeDNSSEC,
		ValidateOnly:        q.ValidateOnly,
		StrictValidation:    q.StrictValidation,
		KeepAlive:           q.KeepAlive,
	}

	logger.Debug("Creating DNS client with options: %+v", opts)
	dnsClient, err := client.New(q.Server, opts)
	if err != nil {
		logger.Error("Failed to create DNS client: %v", err)
		return err
	}
	defer dnsClient.Close()

	qTypeUint, ok := dns.StringToType[strings.ToUpper(q.QueryType)]
	if !ok {
		logger.Error("Invalid query type: %s", q.QueryType)
		return fmt.Errorf("invalid query type: %s", q.QueryType)
	}

	// Prepare DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(q.DomainName), qTypeUint)
	msg.Id = dns.Id()
	msg.RecursionDesired = true

	logger.Debug("Sending DNS query: ID=%d, Question=%s %s", msg.Id, q.DomainName, q.QueryType)
	recvMsg, err := dnsClient.Query(msg)
	if err != nil {
		logger.Error("DNS query failed: %v", err)
		return err
	}

	logger.Debug("Received DNS response: ID=%d, Rcode=%s, Answers=%d",
		recvMsg.Id, dns.RcodeToString[recvMsg.Rcode], len(recvMsg.Answer))
	printResponse(recvMsg.Question[0].Name, q.QueryType, recvMsg)
	return nil
}

func (l *ListenCmd) Run() error {
	config := server.Config{
		Address:             l.Address,
		Upstream:            l.Upstream,
		Fallback:            l.Fallback,
		Bootstrap:           l.Bootstrap,
		DNSSEC:              l.DNSSEC,
		AuthoritativeDNSSEC: l.AuthoritativeDNSSEC,
		KeepAlive:           l.KeepAlive,
		Timeout:             l.Timeout,
		Verbose:             l.Verbose,
	}

	logger.Debug("Server config: %+v", config)
	srv, err := server.New(config)
	if err != nil {
		logger.Error("Failed to create server: %v", err)
		return fmt.Errorf("failed to create server: %w", err)
	}

	logger.Info("Starting DNS proxy server on %s", l.Address)
	logger.Info("Upstream server: %v", l.Upstream)
	logger.Info("Fallback server: %v", l.Fallback)
	logger.Info("Bootstrap server: %v", l.Bootstrap)
	logger.Info("KeepAlive: %v", l.KeepAlive)

	return srv.Start()
}

func printResponse(domain, qtype string, msg *dns.Msg) {
	fmt.Println(";; QUESTION SECTION:")

	fmt.Printf(";%s.\tIN\t%s\n", dns.Fqdn(domain), strings.ToUpper(qtype))

	fmt.Println("\n;; ANSWER SECTION:")
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			fmt.Println(rr.String())
		}
	} else {
		fmt.Println(";; No records found in answer section.")
	}

	if len(msg.Ns) > 0 {
		fmt.Println("\n;; AUTHORITY SECTION:")
		for _, rr := range msg.Ns {
			fmt.Println(rr.String())
		}
	}
	if len(msg.Extra) > 0 {
		hasRealExtra := false
		for _, rr := range msg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				hasRealExtra = true
				break
			}
		}
		if hasRealExtra {
			fmt.Println("\n;; ADDITIONAL SECTION:")
			for _, rr := range msg.Extra {
				if rr.Header().Rrtype != dns.TypeOPT {
					fmt.Println(rr.String())
				}
			}
		}
	}

	fmt.Printf("\n;; RCODE: %s, ID: %d", dns.RcodeToString[msg.Rcode], msg.Id)
	opt := msg.IsEdns0()
	if opt != nil {
		fmt.Printf(", EDNS: version: %d; flags:", opt.Version())
		if opt.Do() {
			fmt.Printf(" do;")
		} else {
			fmt.Printf(";")
		}
		fmt.Printf(" udp: %d", opt.UDPSize())
	}
	fmt.Println()
}

func main() {
	kongCtx := kong.Parse(&cli,
		kong.Name("sdns-proxy"),
		kong.Description("A DNS client/server tool supporting multiple protocols."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true, Summary: true}),
	)

	// Set global debug flag
	logger.SetDebug(cli.Debug)
	logger.Debug("Debug logging enabled")

	err := kongCtx.Run()
	kongCtx.FatalIfErrorf(err)
}
