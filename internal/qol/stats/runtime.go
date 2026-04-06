package stats

import (
	"encoding/csv"
	"fmt"
	"os"
	"runtime"
	"time"
)

type RuntimeStats struct {
	TotalAlloc   uint64
	Mallocs      uint64
	NumGC        uint32
	AllocDelta   uint64
	MallocsDelta uint64
	GCDelta      uint32
}

type RuntimeCollector struct {
	startStats runtime.MemStats
	memPath    string
}

func NewRuntimeCollector(memPath string) *RuntimeCollector {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	return &RuntimeCollector{
		startStats: stats,
		memPath:    memPath,
	}
}

func (rc *RuntimeCollector) Collect() RuntimeStats {
	var current runtime.MemStats
	runtime.ReadMemStats(&current)

	return RuntimeStats{
		TotalAlloc:   current.TotalAlloc,
		Mallocs:      current.Mallocs,
		NumGC:        current.NumGC,
		AllocDelta:   current.TotalAlloc - rc.startStats.TotalAlloc,
		MallocsDelta: current.Mallocs - rc.startStats.Mallocs,
		GCDelta:      current.NumGC - rc.startStats.NumGC,
	}
}

func (rc *RuntimeCollector) WriteStats() error {
	stats := rc.Collect()
	timestamp := time.Now().Format(time.RFC3339Nano)

	// Check if file exists
	fileExists := false
	if _, err := os.Stat(rc.memPath); err == nil {
		fileExists = true
	}

	// Open in append mode
	file, err := os.OpenFile(rc.memPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open mem.csv: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	// Write header if new file
	if !fileExists {
		header := []string{
			"timestamp", "total_alloc_bytes", "mallocs", "gc_cycles",
			"alloc_delta", "mallocs_delta", "gc_delta",
		}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("failed to write mem.csv header: %w", err)
		}
	}

	// Write data row
	row := []string{
		timestamp,
		fmt.Sprintf("%d", stats.TotalAlloc),
		fmt.Sprintf("%d", stats.Mallocs),
		fmt.Sprintf("%d", stats.NumGC),
		fmt.Sprintf("%d", stats.AllocDelta),
		fmt.Sprintf("%d", stats.MallocsDelta),
		fmt.Sprintf("%d", stats.GCDelta),
	}
	if err := writer.Write(row); err != nil {
		return fmt.Errorf("failed to write mem.csv row: %w", err)
	}

	writer.Flush()
	return writer.Error()
}
