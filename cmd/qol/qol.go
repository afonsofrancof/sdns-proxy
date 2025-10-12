package main

import (
	"time"

	"github.com/afonsofrancof/sdns-proxy/internal/qol"
	"github.com/alecthomas/kong"
)

type CLI struct {
	Run RunCmd `cmd:"" help:"Run measurements for given servers and domains"`
}

type RunCmd struct {
	DomainsFile         string        `arg:"" help:"File with domains (one per line)"`
	OutputDir           string        `short:"o" long:"output" default:"results" help:"Output directory"`
	QueryType           string        `short:"t" long:"type" default:"A" help:"DNS query type"`
	Timeout             time.Duration `long:"timeout" default:"5s" help:"Query timeout (informational)"`
	DNSSEC              bool          `long:"dnssec" help:"Enable DNSSEC"`
	AuthoritativeDNSSEC bool          `short:"a" long:"auth-dnssec" help:"Use authoritative DNSSEC validation instead of trusting resolver"`
	KeepAlive           bool          `short:"k" long:"keep-alive" help:"Use persistent connections"`
	Interface           string        `long:"iface" default:"veth1" help:"Capture interface (e.g., eth0, any)"`
	Servers             []string      `short:"s" long:"server" help:"Upstream servers (udp://..., tls://..., https://..., doq://...)"`
}

func (r *RunCmd) Run() error {
	config := qol.MeasurementConfig{
		DomainsFile:         r.DomainsFile,
		OutputDir:           r.OutputDir,
		QueryType:           r.QueryType,
		DNSSEC:              r.DNSSEC,
		AuthoritativeDNSSEC: r.AuthoritativeDNSSEC,
		KeepAlive:           r.KeepAlive,
		Interface:           r.Interface,
		Servers:             r.Servers,
	}

	runner := qol.NewMeasurementRunner(config)
	return runner.Run()
}

func main() {
	ctx := kong.Parse(&CLI{},
		kong.Name("dns-measurer"),
		kong.Description("DNS secure protocols measurer with metrics + full pcap capture"),
		kong.UsageOnError(),
	)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
