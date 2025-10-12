package qol

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afonsofrancof/sdns-proxy/client"
	"github.com/afonsofrancof/sdns-proxy/internal/qol/capture"
	"github.com/afonsofrancof/sdns-proxy/internal/qol/results"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

type MeasurementConfig struct {
	DomainsFile         string
	OutputDir           string
	QueryType           string
	DNSSEC              bool
	AuthoritativeDNSSEC bool
	KeepAlive           bool
	Interface           string
	Servers             []string
}

type MeasurementRunner struct {
	config MeasurementConfig
}

func NewMeasurementRunner(config MeasurementConfig) *MeasurementRunner {
	return &MeasurementRunner{config: config}
}

func (r *MeasurementRunner) Run() error {
	if err := r.checkCapturePermissions(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		fmt.Fprintf(os.Stderr, "Packet capture may fail. Consider running as root/administrator.\n")
	}

	domains, err := r.readDomainsFile()
	if err != nil {
		return fmt.Errorf("failed reading domains: %w", err)
	}

	if len(r.config.Servers) == 0 {
		return fmt.Errorf("at least one server must be provided")
	}

	if err := os.MkdirAll(r.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}

	qType, ok := dns.StringToType[strings.ToUpper(r.config.QueryType)]
	if !ok {
		return fmt.Errorf("invalid qtype: %s", r.config.QueryType)
	}

	for _, upstream := range r.config.Servers {
		if err := r.runPerUpstream(upstream, domains, qType); err != nil {
			fmt.Fprintf(os.Stderr, "error on server %s: %v\n", upstream, err)
		}
	}

	return nil
}

func (r *MeasurementRunner) setupDNSClient(upstream string) (client.DNSClient, error) {
	opts := client.Options{
		DNSSEC:              r.config.DNSSEC,
		AuthoritativeDNSSEC: r.config.AuthoritativeDNSSEC,
		KeepAlive:           r.config.KeepAlive,
	}
	return client.New(upstream, opts)
}

func (r *MeasurementRunner) runPerUpstream(upstream string, domains []string, qType uint16) error {
	// Setup DNS client
	dnsClient, err := r.setupDNSClient(upstream)
	if err != nil {
		return fmt.Errorf("failed creating client: %w", err)
	}
	defer dnsClient.Close()

	// Setup output files
	csvPath, pcapPath := GenerateOutputPaths(r.config.OutputDir, upstream, r.config.DNSSEC, r.config.AuthoritativeDNSSEC, r.config.KeepAlive)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(csvPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	keepAliveStr := ""
	if r.config.KeepAlive {
		keepAliveStr = " (keep-alive)"
	}

	// Show relative path for cleaner output
	relPath, _ := filepath.Rel(r.config.OutputDir, csvPath)
	fmt.Printf(">>> Measuring %s (dnssec=%v, auth=%v%s) → %s\n", upstream, r.config.DNSSEC, r.config.AuthoritativeDNSSEC, keepAliveStr, relPath)

	// Setup packet capture with protocol-aware filtering
	packetCapture, err := capture.NewPacketCapture(r.config.Interface, pcapPath)
	if err != nil {
		return err
	}
	defer packetCapture.Close()

	// Setup results writer
	writer, err := results.NewMetricsWriter(csvPath)
	if err != nil {
		return err
	}
	defer writer.Close()

	time.Sleep(time.Second)
	// Run measurements
	return r.runQueries(dnsClient, upstream, domains, qType, writer, packetCapture)
}

func (r *MeasurementRunner) runQueries(dnsClient client.DNSClient, upstream string,
	domains []string, qType uint16, writer *results.MetricsWriter,
	packetCapture *capture.PacketCapture) error {

	ctx, cancel := context.WithCancel(context.Background())

	if err := packetCapture.Start(ctx); err != nil {
		return err
	}

	failureCount := 0
	const maxFailures = 5
	proto := DetectProtocol(upstream)

	for _, domain := range domains {
		if failureCount >= maxFailures {
			fmt.Printf("⚠ Skipping remaining domains (too many failures: %d)\n", failureCount)
			break
		}

		metric := r.performQuery(dnsClient, domain, upstream, proto, qType)

		if metric.ResponseCode == "ERROR" {
			failureCount++
		} else if metric.ResponseCode == "NOERROR" {
			failureCount = 0
		}

		if err := writer.WriteMetric(metric); err != nil {
			fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
		}

		r.printQueryResult(metric)

		if r.config.KeepAlive {
			time.Sleep(5 * time.Millisecond)
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()

	time.Sleep(100 * time.Millisecond)

	if err := packetCapture.GetError(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: packet capture errors occurred: %v\n", err)
	}

	return nil
}

func (r *MeasurementRunner) performQuery(dnsClient client.DNSClient, domain, upstream, proto string, qType uint16) results.DNSMetric {
	metric := results.DNSMetric{
		Domain:              domain,
		QueryType:           r.config.QueryType,
		Protocol:            proto,
		DNSSEC:              r.config.DNSSEC,
		AuthoritativeDNSSEC: r.config.AuthoritativeDNSSEC,
		KeepAlive:           r.config.KeepAlive,
		DNSServer:           upstream,
	}

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.SetQuestion(dns.Fqdn(domain), qType)

	packed, err := msg.Pack()
	if err != nil {
		metric.ResponseCode = "ERROR"
		metric.Error = fmt.Sprintf("pack request: %v", err)
		return metric
	}
	metric.RequestSize = len(packed)

	start := time.Now()
	metric.Timestamp = start
	resp, err := dnsClient.Query(msg)
	metric.Duration = time.Since(start).Nanoseconds()
	metric.DurationMs = float64(metric.Duration) / 1e6

	if err != nil {
		metric.ResponseCode = "ERROR"
		metric.Error = err.Error()
		return metric
	}

	respBytes, err := resp.Pack()
	if err != nil {
		metric.ResponseCode = "ERROR"
		metric.Error = fmt.Sprintf("pack response: %v", err)
		return metric
	}

	metric.ResponseSize = len(respBytes)
	metric.ResponseCode = dns.RcodeToString[resp.Rcode]
	return metric
}

func (r *MeasurementRunner) printQueryResult(metric results.DNSMetric) {
	statusIcon := "✓"
	if metric.ResponseCode == "ERROR" {
		statusIcon = "✗"
	}

	keepAliveIndicator := ""
	if metric.KeepAlive {
		keepAliveIndicator = "⟷"
	}

	fmt.Printf("%s %s%s [%s] %s %.2fms\n",
		statusIcon, metric.Domain, keepAliveIndicator, metric.Protocol, metric.ResponseCode, metric.DurationMs)
}

func (r *MeasurementRunner) readDomainsFile() ([]string, error) {
	f, err := os.Open(r.config.DomainsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func (r *MeasurementRunner) checkCapturePermissions() error {
	handle, err := pcap.OpenLive("any", 65535, false, time.Millisecond*100)
	if err != nil {
		if strings.Contains(err.Error(), "permission") ||
			strings.Contains(err.Error(), "Operation not permitted") {
			return fmt.Errorf("insufficient permissions for packet capture")
		}
		return nil
	}
	handle.Close()
	return nil
}
