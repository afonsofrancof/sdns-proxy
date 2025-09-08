package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afonsofrancof/sdns-proxy/client"
	"github.com/alecthomas/kong"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/miekg/dns"
)

type CLI struct {
	Run RunCmd `cmd:"" help:"Run measurements for given servers and domains"`
}

type RunCmd struct {
	DomainsFile string        `arg:"" help:"File with domains (one per line)"`
	OutputDir   string        `short:"o" long:"output" default:"results" help:"Output directory"`
	QueryType   string        `short:"t" long:"type" default:"A" help:"DNS query type"`
	Repeat      int           `short:"r" long:"repeat" default:"5" help:"Queries per domain (sequential)"`
	Timeout     time.Duration `long:"timeout" default:"5s" help:"Query timeout (informational)"`
	DNSSEC      bool          `long:"dnssec" help:"Enable DNSSEC"`
	Interface   string        `long:"iface" default:"any" help:"Capture interface (e.g., eth0, any)"`

	Servers []string `short:"s" long:"server" help:"Upstream servers (udp://..., tls://..., https://..., doq://...)"`
}

type DNSMetric struct {
	Domain       string    `json:"domain"`
	QueryType    string    `json:"query_type"`
	Protocol     string    `json:"protocol"`
	DNSSEC       bool      `json:"dnssec"`
	DNSServer    string    `json:"dns_server"`
	Timestamp    time.Time `json:"timestamp"`
	Duration     int64     `json:"duration_ns"`
	DurationMs   float64   `json:"duration_ms"`
	RequestSize  int       `json:"request_size_bytes"`
	ResponseSize int       `json:"response_size_bytes"`
	ResponseCode string    `json:"response_code"`
	Error        string    `json:"error,omitempty"`
}

func (r *RunCmd) Run() error {
	// Check if running with sufficient privileges for packet capture
	if err := checkCapturePermissions(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		fmt.Fprintf(os.Stderr, "Packet capture may fail. Consider running as root/administrator.\n")
	}

	domains, err := readDomainsFile(r.DomainsFile)
	if err != nil {
		return fmt.Errorf("failed reading domains: %w", err)
	}
	if len(r.Servers) == 0 {
		return fmt.Errorf("at least one --server must be provided")
	}
	if err := os.MkdirAll(r.OutputDir, 0755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}

	qType, ok := dns.StringToType[strings.ToUpper(r.QueryType)]
	if !ok {
		return fmt.Errorf("invalid qtype: %s", r.QueryType)
	}

	for _, upstream := range r.Servers {
		if err := r.runOne(upstream, domains, qType); err != nil {
			fmt.Fprintf(os.Stderr, "error on server %s: %v\n", upstream, err)
		}
	}
	return nil
}

func (r *RunCmd) runOne(upstream string, domains []string, qType uint16) error {
	opts := client.Options{DNSSEC: r.DNSSEC}
	dnsClient, err := client.New(upstream, opts)
	if err != nil {
		return fmt.Errorf("failed creating client: %w", err)
	}
	defer dnsClient.Close()

	// file naming
	proto := detectProtocol(upstream)
	ts := time.Now().Format("20060102_1504")
	dnssecStr := "off"
	if r.DNSSEC {
		dnssecStr = "on"
	}
	base := fmt.Sprintf("%s_%s_dnssec_%s_%s",
		proto, sanitize(upstream), dnssecStr, ts)
	jsonPath := filepath.Join(r.OutputDir, base+".jsonl")
	pcapPath := filepath.Join(r.OutputDir, base+".pcap")

	fmt.Printf(">>> Measuring %s (dnssec=%v) → %s\n", upstream, r.DNSSEC, base)

	// setup pcap capture
	handle, err := pcap.OpenLive(r.Interface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open (try running as root): %w", err)
	}
	defer handle.Close()

	pcapFile, err := os.Create(pcapPath)
	if err != nil {
		return fmt.Errorf("create pcap file: %w", err)
	}
	defer pcapFile.Close()

	writer := pcapgo.NewWriter(pcapFile)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		return fmt.Errorf("pcap header: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psrc := gopacket.NewPacketSource(handle, handle.LinkType())
	pktCh := psrc.Packets()

	var wg sync.WaitGroup
	var captureErr error
	captureMutex := sync.Mutex{}

	// Start packet capture goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt, ok := <-pktCh:
				if !ok {
					return
				}
				ci := pkt.Metadata().CaptureInfo
				if err := writer.WritePacket(ci, pkt.Data()); err != nil {
					captureMutex.Lock()
					if captureErr == nil {
						captureErr = fmt.Errorf("pcap write error: %w", err)
					}
					captureMutex.Unlock()
					fmt.Fprintf(os.Stderr, "pcap write error: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// open JSONL output
	out, err := os.Create(jsonPath)
	if err != nil {
		cancel()
		wg.Wait()
		return fmt.Errorf("create json out: %w", err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)

	// sequential measurement
	for _, domain := range domains {
		for rep := 0; rep < r.Repeat; rep++ {
			metric := performQuery(dnsClient, domain, upstream, proto, qType, r.QueryType, r.DNSSEC)
			if err := enc.Encode(metric); err != nil {
				fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
			}
			fmt.Printf("✓ %s [%s] %s %.2fms\n",
				metric.Domain, metric.Protocol, metric.ResponseCode, metric.DurationMs)
			
			// Small delay to allow packet capture to catch up
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Allow some time for final packets to be captured
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()

	// Check if there were capture errors
	captureMutex.Lock()
	defer captureMutex.Unlock()
	if captureErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: packet capture errors occurred: %v\n", captureErr)
	}

	return nil
}

func performQuery(dnsClient client.DNSClient, domain, upstream, proto string,
	qType uint16, qTypeStr string, dnssec bool) DNSMetric {

	metric := DNSMetric{
		Domain:    domain,
		QueryType: qTypeStr,
		Protocol:  proto,
		DNSSEC:    dnssec,
		DNSServer: upstream,
		Timestamp: time.Now(),
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

func readDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
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

func sanitize(s string) string {
	return strings.NewReplacer(":", "_", "/", "_").Replace(s)
}

func detectProtocol(upstream string) string {
	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err == nil && u.Scheme != "" {
			return strings.ToLower(u.Scheme)
		}
	}
	return "do53"
}

func checkCapturePermissions() error {
	// Try to open a test interface to check permissions
	handle, err := pcap.OpenLive("any", 65535, false, time.Millisecond*100)
	if err != nil {
		if strings.Contains(err.Error(), "permission") || 
		   strings.Contains(err.Error(), "Operation not permitted") {
			return fmt.Errorf("insufficient permissions for packet capture")
		}
		// Other errors might be due to interface availability, which is acceptable
		return nil
	}
	handle.Close()
	return nil
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
