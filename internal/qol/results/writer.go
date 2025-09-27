package results

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type DNSMetric struct {
	Domain       string    `json:"domain"`
	QueryType    string    `json:"query_type"`
	Protocol     string    `json:"protocol"`
	DNSSEC       bool      `json:"dnssec"`
	KeepAlive    bool      `json:"keep_alive"`
	DNSServer    string    `json:"dns_server"`
	Timestamp    time.Time `json:"timestamp"`
	Duration     int64     `json:"duration_ns"`
	DurationMs   float64   `json:"duration_ms"`
	RequestSize  int       `json:"request_size_bytes"`
	ResponseSize int       `json:"response_size_bytes"`
	ResponseCode string    `json:"response_code"`
	Error        string    `json:"error,omitempty"`
}

// Rest stays exactly the same
type MetricsWriter struct {
	encoder *json.Encoder
	file    *os.File
}

func NewMetricsWriter(path string) (*MetricsWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create json output: %w", err)
	}

	return &MetricsWriter{
		encoder: json.NewEncoder(file),
		file:    file,
	}, nil
}

func (mw *MetricsWriter) WriteMetric(metric DNSMetric) error {
	return mw.encoder.Encode(metric)
}

func (mw *MetricsWriter) Close() error {
	if mw.file != nil {
		return mw.file.Close()
	}
	return nil
}
