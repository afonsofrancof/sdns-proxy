package capture

import (
	"context"
	"fmt"
	"os"
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

func NewPacketCapture(iface, outputPath string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open (try running as root): %w", err)
	}

	// Check if file exists
	fileExists := false
	if _, err := os.Stat(outputPath); err == nil {
		fileExists = true
	}

	var file *os.File
	if fileExists {
		file, err = os.OpenFile(outputPath, os.O_APPEND, 0644)
	} else {
		file, err = os.Create(outputPath)
	}
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("create/open pcap file: %w", err)
	}

	writer := pcapgo.NewWriter(file)

	// Only write header if file is new
	if !fileExists {
		if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
			handle.Close()
			file.Close()
			return nil, fmt.Errorf("pcap header: %w", err)
		}
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
			case <-ctx.Done():
				return
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
