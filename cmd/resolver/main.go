package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/afonsofrancof/sdns-perf/internal/client"

	"github.com/alecthomas/kong"
	"github.com/miekg/dns"
)

var cli struct {
	// Global flags
	Verbose bool `help:"Enable verbose logging." short:"v"`

	Query  QueryCmd  `cmd:"" help:"Perform a DNS query (client mode)."`
	Listen ListenCmd `cmd:"" help:"Run as a DNS listener/resolver (server mode)."`
}

type QueryCmd struct {
	DomainName string        `help:"Domain name to resolve." arg:"" required:""`
	Server     string        `help:"Upstream server address (e.g., https://1.1.1.1/dns-query, tls://1.1.1.1, 8.8.8.8)." short:"s" required:""`
	QueryType  string        `help:"Query type (A, AAAA, MX, TXT, etc.)." short:"t" enum:"A,AAAA,MX,TXT,NS,CNAME,SOA,PTR" default:"A"`
	DNSSEC     bool          `help:"Enable DNSSEC (DO bit)." short:"d"`
	Timeout    time.Duration `help:"Timeout for the query operation." default:"10s"` // Default might be higher now
	KeyLogFile string        `help:"Path to TLS key log file (for DoT/DoH/DoQ)." env:"SSLKEYLOGFILE"`
}

func (q *QueryCmd) Run() error {
	log.Printf("Querying %s for %s type %s (DNSSEC: %v, Timeout: %v)\n",
		q.Server, q.DomainName, q.QueryType, q.DNSSEC, q.Timeout)

	opts := client.Options{
		Timeout:    q.Timeout,
		DNSSEC:     q.DNSSEC,
		KeyLogPath: q.KeyLogFile,
	}

	dnsClient, err := client.New(q.Server, opts)
	if err != nil {
		return err
	}
	defer dnsClient.Close()

	qTypeUint, ok := dns.StringToType[strings.ToUpper(q.QueryType)]
	if !ok {
		return fmt.Errorf("invalid query type: %s", q.QueryType)
	}

	dnsMsg, err := dnsClient.Query(q.DomainName, qTypeUint)
	if err != nil {
		return fmt.Errorf("query failed: %w ", err)
	}

	printResponse(q.DomainName, q.QueryType, dnsMsg)

	return nil
}

type ListenCmd struct {
	Address string `help:"Address to listen on (e.g., :53, :8053)." default:":53"`
	// Add other server-specific flags: default upstream, TLS cert/key paths etc.
}

func (l *ListenCmd) Run() error {
	return fmt.Errorf("server/listen mode not yet implemented")
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
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lshortfile)

	kongCtx := kong.Parse(&cli,
		kong.Name("sdns-perf"),
		kong.Description("A DNS client/server tool supporting multiple protocols."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true, Summary: true}),
	)

	err := kongCtx.Run()
	kongCtx.FatalIfErrorf(err)
}
