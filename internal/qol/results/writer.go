package results

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

type DNSMetric struct {
	Domain              string    `json:"domain"`
	QueryType           string    `json:"query_type"`
	Protocol            string    `json:"protocol"`
	DNSSEC              bool      `json:"dnssec"`
	AuthoritativeDNSSEC bool      `json:"auth_dnssec"`
	KeepAlive           bool      `json:"keep_alive"`
	DNSServer           string    `json:"dns_server"`
	Timestamp           time.Time `json:"timestamp"`
	Duration            int64     `json:"duration_ns"`
	DurationMs          float64   `json:"duration_ms"`
	RequestSize         int       `json:"request_size_bytes"`
	ResponseSize        int       `json:"response_size_bytes"`
	ResponseCode        string    `json:"response_code"`
	Error               string    `json:"error,omitempty"`
}

type MetricsWriter struct {
	writer *csv.Writer
	file   *os.File
}

func NewMetricsWriter(path string) (*MetricsWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create csv output: %w", err)
	}

	writer := csv.NewWriter(file)

	// Write CSV header
	header := []string{
		"domain", "query_type", "protocol", "dnssec", "auth_dnssec", "keep_alive",
		"dns_server", "timestamp", "duration_ns", "duration_ms",
		"request_size_bytes", "response_size_bytes", "response_code", "error",
	}

	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("write csv header: %w", err)
	}

	writer.Flush()

	return &MetricsWriter{
		writer: writer,
		file:   file,
	}, nil
}

func (mw *MetricsWriter) WriteMetric(metric DNSMetric) error {
	record := []string{
		metric.Domain,
		metric.QueryType,
		metric.Protocol,
		strconv.FormatBool(metric.DNSSEC),
		strconv.FormatBool(metric.AuthoritativeDNSSEC),
		strconv.FormatBool(metric.KeepAlive),
		metric.DNSServer,
		metric.Timestamp.Format(time.RFC3339),
		strconv.FormatInt(metric.Duration, 10),
		strconv.FormatFloat(metric.DurationMs, 'f', 3, 64),
		strconv.Itoa(metric.RequestSize),
		strconv.Itoa(metric.ResponseSize),
		metric.ResponseCode,
		metric.Error,
	}

	err := mw.writer.Write(record)
	if err != nil {
		return err
	}

	mw.writer.Flush()
	return mw.writer.Error()
}

func (mw *MetricsWriter) Close() error {
	if mw.writer != nil {
		mw.writer.Flush()
	}
	if mw.file != nil {
		return mw.file.Close()
	}
	return nil
}
