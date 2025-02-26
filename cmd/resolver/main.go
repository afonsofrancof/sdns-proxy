package main

import (
	"log"

	"github.com/afonsofrancof/sdns-perf/internal/protocols/do53"
	"github.com/afonsofrancof/sdns-perf/internal/protocols/doh"
	"github.com/alecthomas/kong"
)

type CommonFlags struct {
	DomainName string `help:"Domain name to resolve" arg:"" required:""`
	QueryType  string `help:"Query type" enum:"A,AAAA,MX,TXT,NS,CNAME,SOA,PTR" default:"A"`
	Server     string `help:"DNS server to use"`
	DNSSEC     bool   `help:"Enable DNSSEC validation"`
}

type DoHCmd struct {
	CommonFlags `embed:""`
	HTTP3       bool   `help:"Use HTTP/3" name:"http3"`
	Path        string `help:"The HTTP path for the POST request" name:"path" required:""`
	Proxy       string `help:"The Proxy to use with ODoH"`
}

type DoTCmd struct {
	CommonFlags
}

type DoQCmd struct {
	CommonFlags
}

type Do53Cmd struct {
	CommonFlags
}

var cli struct {
	Verbose bool `help:"Enable verbose logging" short:"v"`

	DoH  DoHCmd  `cmd:"doh" help:"Query using DNS-over-HTTPS" name:"doh"`
	DoT  DoTCmd  `cmd:"dot" help:"Query using DNS-over-TLS" name:"dot"`
	DoQ  DoQCmd  `cmd:"doq" help:"Query using DNS-over-QUIC" name:"doq"`
	Do53 Do53Cmd `cmd:"doq" help:"Query using plain DNS over UDP" name:"do53"`
}

func (c *Do53Cmd) Run() error {
	return do53.Run(c.DomainName, c.QueryType, c.Server, c.DNSSEC)
}

func (c *DoHCmd) Run() error {
	return doh.Run(c.DomainName, c.QueryType, c.Server, c.Path,c.Proxy, c.DNSSEC)
}

func (c *DoTCmd) Run() error {
	// TODO: Implement DoT query
	return nil
}

func (c *DoQCmd) Run() error {
	// TODO: Implement DoQ query
	return nil
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("dns-go"),
		kong.Description("A DNS resolver supporting DoH, DoT, and DoQ protocols"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))

	err := ctx.Run()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
