package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type QueryRecord struct {
	Domain              string
	QueryType           string
	Protocol            string
	DNSSec              string
	AuthDNSSec          string
	KeepAlive           string
	DNSServer           string
	Timestamp           string
	DurationNs          int64
	DurationMs          float64
	RequestSizeBytes    int
	ResponseSizeBytes   int
	ResponseCode        string
	Error               string
	BytesSent           int64
	BytesReceived       int64
	PacketsSent         int64
	PacketsReceived     int64
	TotalBytes          int64
}

func parseRFC3339Nano(ts string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, ts)
}

func processProviderFolder(providerPath string) error {
	providerName := filepath.Base(providerPath)
	fmt.Printf("\n=== Processing provider: %s ===\n", providerName)
	
	files, err := os.ReadDir(providerPath)
	if err != nil {
		return err
	}

	processed := 0
	skipped := 0
	errors := 0

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".csv") {
			continue
		}

		csvPath := filepath.Join(providerPath, file.Name())
		pcapPath := strings.Replace(csvPath, ".csv", ".pcap", 1)
		
		// Check if PCAP exists
		if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
			fmt.Printf("  ⊗ Skipping: %s (no matching PCAP)\n", file.Name())
			skipped++
			continue
		}

		// Check if already processed (has backup)
		backupPath := csvPath + ".bak"
		if _, err := os.Stat(backupPath); err == nil {
			fmt.Printf("  ⊙ Skipping: %s (already processed, backup exists)\n", file.Name())
			skipped++
			continue
		}

		fmt.Printf("  ↻ Processing: %s ... ", file.Name())
		if err := processPair(csvPath, pcapPath); err != nil {
			fmt.Printf("ERROR\n")
			log.Printf("    Error: %v\n", err)
			errors++
		} else {
			fmt.Printf("✓\n")
			processed++
		}
	}

	fmt.Printf("  Summary: %d processed, %d skipped, %d errors\n", processed, skipped, errors)
	return nil
}

func processPair(csvPath, pcapPath string) error {
	// Create backup
	backupPath := csvPath + ".bak"
	input, err := os.ReadFile(csvPath)
	if err != nil {
		return fmt.Errorf("backup read failed: %w", err)
	}
	if err := os.WriteFile(backupPath, input, 0644); err != nil {
		return fmt.Errorf("backup write failed: %w", err)
	}

	// Read CSV records
	records, err := readCSV(csvPath)
	if err != nil {
		return fmt.Errorf("CSV read failed: %w", err)
	}

	if len(records) == 0 {
		return fmt.Errorf("no records in CSV")
	}

	// Read and parse PCAP
	packets, err := readPCAPGo(pcapPath)
	if err != nil {
		return fmt.Errorf("PCAP read failed: %w", err)
	}

	// Enrich records with bandwidth data
	enrichRecords(records, packets)

	// Write enriched CSV
	if err := writeCSV(csvPath, records); err != nil {
		return fmt.Errorf("CSV write failed: %w", err)
	}

	return nil
}

func readCSV(path string) ([]*QueryRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV has no data rows")
	}

	records := make([]*QueryRecord, 0, len(rows)-1)
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		if len(row) < 14 {
			log.Printf("    Warning: Skipping malformed row %d", i+1)
			continue
		}

		durationNs, _ := strconv.ParseInt(row[8], 10, 64)
		durationMs, _ := strconv.ParseFloat(row[9], 64)
		reqSize, _ := strconv.Atoi(row[10])
		respSize, _ := strconv.Atoi(row[11])

		records = append(records, &QueryRecord{
			Domain:            row[0],
			QueryType:         row[1],
			Protocol:          row[2],
			DNSSec:            row[3],
			AuthDNSSec:        row[4],
			KeepAlive:         row[5],
			DNSServer:         row[6],
			Timestamp:         row[7],
			DurationNs:        durationNs,
			DurationMs:        durationMs,
			RequestSizeBytes:  reqSize,
			ResponseSizeBytes: respSize,
			ResponseCode:      row[12],
			Error:             row[13],
		})
	}

	return records, nil
}

type PacketInfo struct {
	Timestamp time.Time
	Size      int
	IsSent    bool
}

func readPCAPGo(path string) ([]PacketInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}

	var packets []PacketInfo
	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil {
			continue
		}

		isDNS := false
		isSent := false

		// Check UDP layer (DNS, DoQ, DoH3)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			isDNS = udp.SrcPort == 53 || udp.DstPort == 53 ||
				udp.SrcPort == 853 || udp.DstPort == 853 ||
				udp.SrcPort == 443 || udp.DstPort == 443
			isSent = udp.DstPort == 53 || udp.DstPort == 853 || udp.DstPort == 443
		}

		// Check TCP layer (DoT, DoH)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			isDNS = tcp.SrcPort == 53 || tcp.DstPort == 53 ||
				tcp.SrcPort == 853 || tcp.DstPort == 853 ||
				tcp.SrcPort == 443 || tcp.DstPort == 443
			isSent = tcp.DstPort == 53 || tcp.DstPort == 853 || tcp.DstPort == 443
		}

		if isDNS {
			packets = append(packets, PacketInfo{
				Timestamp: packet.Metadata().Timestamp,
				Size:      len(packet.Data()),
				IsSent:    isSent,
			})
		}
	}

	return packets, nil
}

func enrichRecords(records []*QueryRecord, packets []PacketInfo) {
	for _, rec := range records {
		ts, err := parseRFC3339Nano(rec.Timestamp)
		if err != nil {
			log.Printf("    Warning: Failed to parse timestamp: %s", rec.Timestamp)
			continue
		}

		// Define time window for this query
		windowStart := ts
		windowEnd := ts.Add(time.Duration(rec.DurationNs))

		var sent, recv, pktSent, pktRecv int64

		// Match packets within the time window
		for _, pkt := range packets {
			if (pkt.Timestamp.Equal(windowStart) || pkt.Timestamp.After(windowStart)) &&
				pkt.Timestamp.Before(windowEnd) {
				if pkt.IsSent {
					sent += int64(pkt.Size)
					pktSent++
				} else {
					recv += int64(pkt.Size)
					pktRecv++
				}
			}
		}

		rec.BytesSent = sent
		rec.BytesReceived = recv
		rec.PacketsSent = pktSent
		rec.PacketsReceived = pktRecv
		rec.TotalBytes = sent + recv
	}
}

func writeCSV(path string, records []*QueryRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	header := []string{
		"domain", "query_type", "protocol", "dnssec", "auth_dnssec",
		"keep_alive", "dns_server", "timestamp", "duration_ns", "duration_ms",
		"request_size_bytes", "response_size_bytes", "response_code", "error",
		"bytes_sent", "bytes_received", "packets_sent", "packets_received", "total_bytes",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, rec := range records {
		row := []string{
			rec.Domain,
			rec.QueryType,
			rec.Protocol,
			rec.DNSSec,
			rec.AuthDNSSec,
			rec.KeepAlive,
			rec.DNSServer,
			rec.Timestamp,
			strconv.FormatInt(rec.DurationNs, 10),
			strconv.FormatFloat(rec.DurationMs, 'f', -1, 64),
			strconv.Itoa(rec.RequestSizeBytes),
			strconv.Itoa(rec.ResponseSizeBytes),
			rec.ResponseCode,
			rec.Error,
			strconv.FormatInt(rec.BytesSent, 10),
			strconv.FormatInt(rec.BytesReceived, 10),
			strconv.FormatInt(rec.PacketsSent, 10),
			strconv.FormatInt(rec.PacketsReceived, 10),
			strconv.FormatInt(rec.TotalBytes, 10),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	resultsDir := "results"
	providers := []string{"adguard", "cloudflare", "google", "quad9"}

	fmt.Println("╔═══════════════════════════════════════════════╗")
	fmt.Println("║   DNS PCAP Preprocessor v1.0                  ║")
	fmt.Println("║   Enriching ALL CSVs with bandwidth metrics   ║")
	fmt.Println("╚═══════════════════════════════════════════════╝")

	totalProcessed := 0
	totalSkipped := 0
	totalErrors := 0

	for _, provider := range providers {
		providerPath := filepath.Join(resultsDir, provider)
		if _, err := os.Stat(providerPath); os.IsNotExist(err) {
			fmt.Printf("\n⚠ Provider folder not found: %s\n", provider)
			continue
		}

		if err := processProviderFolder(providerPath); err != nil {
			log.Printf("Error processing %s: %v\n", provider, err)
			totalErrors++
		}
	}

	fmt.Println("\n╔═══════════════════════════════════════════════╗")
	fmt.Println("║   Preprocessing Complete!                     ║")
	fmt.Println("╚═══════════════════════════════════════════════╝")
	fmt.Printf("\nAll CSV files now have 5 additional columns:\n")
	fmt.Printf("  • bytes_sent          - Total bytes sent to DNS server\n")
	fmt.Printf("  • bytes_received      - Total bytes received from DNS server\n")
	fmt.Printf("  • packets_sent        - Number of packets sent\n")
	fmt.Printf("  • packets_received    - Number of packets received\n")
	fmt.Printf("  • total_bytes         - Sum of sent + received bytes\n")
	fmt.Printf("\n📁 Backups saved as: *.csv.bak\n")
	fmt.Printf("\n💡 Tip: The analysis script will filter which files to visualize,\n")
	fmt.Printf("   but all files now have complete bandwidth metrics!\n")
}
