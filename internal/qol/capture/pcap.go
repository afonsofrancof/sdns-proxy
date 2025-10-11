package capture

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type PacketCapture struct {
	handle *pcap.Handle
	writer *pcapgo.Writer
	file   *os.File
	mu     sync.Mutex
	err    error
}

func getLocalIPs() ([]string, error) {
	var localIPs []string
	
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}
	
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		
		// Skip loopback
		if ip == nil || ip.IsLoopback() {
			continue
		}
		
		localIPs = append(localIPs, ip.String())
	}
	
	if len(localIPs) == 0 {
		return nil, fmt.Errorf("no non-loopback IPs found")
	}
	
	return localIPs, nil
}

func buildBPFFilter(protocol string, localIPs []string) string {
	// Build filter for this machine's IPs
	var hostFilters []string
	for _, ip := range localIPs {
		hostFilters = append(hostFilters, fmt.Sprintf("host %s", ip))
	}
	testMachineFilter := "(" + strings.Join(hostFilters, " or ") + ")"
	
	// Protocol-specific ports
	var portFilter string
	switch strings.ToLower(protocol) {
	case "udp":
		portFilter = "(port 53)"
	case "tls", "dot":
		portFilter = "(port 53 or port 853)"
	case "https", "doh":
		portFilter = "(port 53 or port 443)"
	case "doq":
		portFilter = "(port 53 or port 853)"
	case "doh3":
		portFilter = "(port 53 or port 443)"
	default:
		portFilter = "(port 53 or port 443 or port 853)"
	}
	
	// Exclude private-to-private traffic (LAN-to-LAN, includes Docker ranges)
	privateExclude := "not (src net (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16) and dst net (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16))"
	
	// Combine: test machine AND protocol ports AND NOT (private to private)
	return testMachineFilter + " and " + portFilter + " and " + privateExclude
}

func NewPacketCapture(iface, outputPath, protocol string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open (try running as root): %w", err)
	}

	// Get local IPs dynamically
	localIPs, err := getLocalIPs()
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to get local IPs: %w", err)
	}

	// Build and apply BPF filter
	bpfFilter := buildBPFFilter(protocol, localIPs)
	
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter '%s': %w", bpfFilter, err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("create pcap file: %w", err)
	}

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		handle.Close()
		file.Close()
		return nil, fmt.Errorf("pcap header: %w", err)
	}

	return &PacketCapture{
		handle: handle,
		writer: writer,
		file:   file,
	}, nil
}

func (pc *PacketCapture) Start(ctx context.Context) error {
	psrc := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	pktCh := psrc.Packets()

	go func() {
		for {
			select {
			case pkt, ok := <-pktCh:
				if !ok {
					return
				}
				ci := pkt.Metadata().CaptureInfo
				if err := pc.writer.WritePacket(ci, pkt.Data()); err != nil {
					pc.mu.Lock()
					if pc.err == nil {
						pc.err = fmt.Errorf("pcap write error: %w", err)
					}
					pc.mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (pc *PacketCapture) GetError() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.err
}

func (pc *PacketCapture) Close() error {
	var errs []error
	
	if pc.handle != nil {
		pc.handle.Close()
	}
	
	if pc.file != nil {
		if err := pc.file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	
	if len(errs) > 0 {
		return errs[0]
	}
	
	return nil
}
