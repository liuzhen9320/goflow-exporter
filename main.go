// main.go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// Configuration structures
type Config struct {
	Server struct {
		ListenAddresses []string `yaml:"listen_addresses"`
		Ports           struct {
			NetFlow int `yaml:"netflow"`
			IPFIX   int `yaml:"ipfix"`
			SFlow   int `yaml:"sflow"`
		} `yaml:"ports"`
		MetricsPort    int    `yaml:"metrics_port"`
		MetricsPath    string `yaml:"metrics_path"`
		ReadBufferSize int    `yaml:"read_buffer_size"`
		Workers        int    `yaml:"workers"`
		BatchSize      int    `yaml:"batch_size"`
	} `yaml:"server"`

	Logging struct {
		Level      string `yaml:"level"`
		Structured bool   `yaml:"structured"`
	} `yaml:"logging"`

	Metrics struct {
		Namespace string `yaml:"namespace"`
		Subsystem string `yaml:"subsystem"`
		Labels    struct {
			EnableGeoIP bool     `yaml:"enable_geoip"`
			EnableASN   bool     `yaml:"enable_asn"`
			Dimensions  []string `yaml:"dimensions"`
		} `yaml:"labels"`
	} `yaml:"metrics"`

	Aggregation struct {
		TimeWindows []string `yaml:"time_windows"`
		Dimensions  []string `yaml:"dimensions"`
	} `yaml:"aggregation"`

	GeoIP struct {
		DatabasePath    string `yaml:"database_path"`
		ASNDatabasePath string `yaml:"asn_database_path"`
		CacheSize       int    `yaml:"cache_size"`
		CacheTTL        string `yaml:"cache_ttl"`
	} `yaml:"geoip"`
}

// Flow record structures
type FlowRecord struct {
	SrcAddr     net.IP
	DstAddr     net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Bytes       uint64
	Packets     uint64
	InputIface  uint32
	OutputIface uint32
	FirstSeen   time.Time
	LastSeen    time.Time
}

type FlowKey struct {
	SrcAddr     string
	DstAddr     string
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	InputIface  uint32
	OutputIface uint32
}

type AggregatedFlow struct {
	Bytes     uint64
	Packets   uint64
	Flows     uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// GeoIP cache entry
type GeoIPEntry struct {
	Country string
	City    string
	ASN     uint32
	ASOrg   string
	Expiry  time.Time
}

// Protocol constants
const (
	NETFLOW_V9 = 9
	IPFIX_V10  = 10
	SFLOW_V5   = 5
)

// NetFlow v9 structures
type NetFlowV9Header struct {
	Version       uint16
	Count         uint16
	SysUptime     uint32
	UnixSecs      uint32
	SequenceNum   uint32
	SourceID      uint32
}

type NetFlowV9FlowSet struct {
	FlowSetID uint16
	Length    uint16
}

type NetFlowV9Template struct {
	TemplateID   uint16
	FieldCount   uint16
	Fields       []NetFlowV9Field
}

type NetFlowV9Field struct {
	Type   uint16
	Length uint16
}

// IPFIX structures
type IPFIXHeader struct {
	Version             uint16
	Length              uint16
	ExportTime          uint32
	SequenceNum         uint32
	ObservationDomainID uint32
}

// sFlow structures
type SFlowHeader struct {
	Version        uint32
	AddressType    uint32
	AgentAddress   [16]byte
	SubAgentID     uint32
	SequenceNum    uint32
	SysUptime      uint32
	NumSamples     uint32
}

// SFlow Sample types
const (
	SFLOW_FLOW_SAMPLE     = 1
	SFLOW_COUNTER_SAMPLE  = 2
	SFLOW_EXPANDED_SAMPLE = 3
)

type SFlowFlowSample struct {
	SampleType       uint32
	SampleLength     uint32
	SequenceNum      uint32
	SourceIDType     uint32
	SourceIDIndex    uint32
	SamplingRate     uint32
	SamplePool       uint32
	DroppedPackets   uint32
	InputInterface   uint32
	OutputInterface  uint32
	NumRecords       uint32
}

// Main collector structure
type FlowCollector struct {
	config    *Config
	logger    *log.Logger
	geoipDB   *geoip2.Reader
	asnDB     *geoip2.Reader
	geoCache  sync.Map
	templates sync.Map

	// Metrics
	flowsTotal          *prometheus.CounterVec
	bytesTotal          *prometheus.CounterVec
	packetsTotal        *prometheus.CounterVec
	bandwidthGauge      *prometheus.GaugeVec
	receivedPackets     prometheus.Counter
	parsedRecords       prometheus.Counter
	droppedRecords      prometheus.Counter
	processingDuration  prometheus.Histogram
	workerQueueLength   prometheus.Gauge

	// Aggregation
	aggregatedFlows   map[string]map[FlowKey]AggregatedFlow
	aggregationMutex  sync.RWMutex
	timeWindowMutexes map[string]*sync.RWMutex

	// Channels
	flowChan chan FlowRecord
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.Server.MetricsPort == 0 {
		config.Server.MetricsPort = 8080
	}
	if config.Server.MetricsPath == "" {
		config.Server.MetricsPath = "/metrics"
	}
	if config.Server.ReadBufferSize == 0 {
		config.Server.ReadBufferSize = 8192
	}
	if config.Server.Workers == 0 {
		config.Server.Workers = 4
	}
	if config.Server.BatchSize == 0 {
		config.Server.BatchSize = 100
	}
	if config.Metrics.Namespace == "" {
		config.Metrics.Namespace = "flow"
	}
	if config.Metrics.Subsystem == "" {
		config.Metrics.Subsystem = "collector"
	}
	if len(config.Aggregation.TimeWindows) == 0 {
		config.Aggregation.TimeWindows = []string{"1m", "5m", "15m", "1h"}
	}
	if config.GeoIP.CacheTTL == "" {
		config.GeoIP.CacheTTL = "1h"
	}
	if config.GeoIP.CacheSize == 0 {
		config.GeoIP.CacheSize = 10000
	}

	return &config, nil
}

func NewFlowCollector(config *Config) (*FlowCollector, error) {
	logger := log.New(os.Stdout)
	if config.Logging.Structured {
		logger.SetReportCaller(false)
		logger.SetTimeFormat(time.Kitchen)
	}

	// Set log level
	switch strings.ToLower(config.Logging.Level) {
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "info":
		logger.SetLevel(log.InfoLevel)
	case "warn":
		logger.SetLevel(log.WarnLevel)
	case "error":
		logger.SetLevel(log.ErrorLevel)
	default:
		logger.SetLevel(log.InfoLevel)
	}

	collector := &FlowCollector{
		config:            config,
		logger:            logger,
		flowChan:          make(chan FlowRecord, config.Server.BatchSize*10),
		stopChan:          make(chan struct{}),
		aggregatedFlows:   make(map[string]map[FlowKey]AggregatedFlow),
		timeWindowMutexes: make(map[string]*sync.RWMutex),
	}

	// Initialize time window maps
	for _, window := range config.Aggregation.TimeWindows {
		collector.aggregatedFlows[window] = make(map[FlowKey]AggregatedFlow)
		collector.timeWindowMutexes[window] = &sync.RWMutex{}
	}

	// Initialize GeoIP databases
	if config.Metrics.Labels.EnableGeoIP && config.GeoIP.DatabasePath != "" {
		db, err := geoip2.Open(config.GeoIP.DatabasePath)
		if err != nil {
			logger.Warn("Failed to open GeoIP database", "error", err, "path", config.GeoIP.DatabasePath)
		} else {
			collector.geoipDB = db
			logger.Info("GeoIP database loaded", "path", config.GeoIP.DatabasePath)
		}
	}

	if config.Metrics.Labels.EnableASN && config.GeoIP.ASNDatabasePath != "" {
		db, err := geoip2.Open(config.GeoIP.ASNDatabasePath)
		if err != nil {
			logger.Warn("Failed to open ASN database", "error", err, "path", config.GeoIP.ASNDatabasePath)
		} else {
			collector.asnDB = db
			logger.Info("ASN database loaded", "path", config.GeoIP.ASNDatabasePath)
		}
	}

	// Initialize Prometheus metrics
	collector.initMetrics()

	return collector, nil
}

func (fc *FlowCollector) initMetrics() {
	labels := []string{"protocol"}

	// Add optional labels based on configuration
	validDims := map[string]bool{"src_port": true, "dst_port": true, "input_iface": true, "output_iface": true}
	for _, dim := range fc.config.Metrics.Labels.Dimensions {
		if validDims[dim] {
			labels = append(labels, dim)
		}
	}

	if fc.config.Metrics.Labels.EnableGeoIP {
		labels = append(labels, "src_country", "dst_country")
	}

	if fc.config.Metrics.Labels.EnableASN {
		labels = append(labels, "src_asn", "dst_asn")
	}

	fc.flowsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "flows_total",
			Help:      "Total number of flows processed",
		},
		labels,
	)

	fc.bytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "bytes_total",
			Help:      "Total number of bytes processed",
		},
		labels,
	)

	fc.packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "packets_total",
			Help:      "Total number of packets processed",
		},
		labels,
	)

	fc.bandwidthGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "bandwidth_bps",
			Help:      "Bandwidth utilization in bits per second",
		},
		[]string{"direction", "interface"},
	)

	// System metrics
	fc.receivedPackets = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "received_packets_total",
			Help:      "Total number of received raw packets",
		},
	)

	fc.parsedRecords = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "parsed_records_total",
			Help:      "Total number of successfully parsed flow records",
		},
	)

	fc.droppedRecords = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "dropped_records_total",
			Help:      "Total number of dropped or failed records",
		},
	)

	fc.processingDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "processing_duration_seconds",
			Help:      "Processing duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
	)

	fc.workerQueueLength = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: fc.config.Metrics.Namespace,
			Subsystem: fc.config.Metrics.Subsystem,
			Name:      "worker_queue_length",
			Help:      "Current length of worker processing queue",
		},
	)

	// Register metrics
	prometheus.MustRegister(fc.flowsTotal)
	prometheus.MustRegister(fc.bytesTotal)
	prometheus.MustRegister(fc.packetsTotal)
	prometheus.MustRegister(fc.bandwidthGauge)
	prometheus.MustRegister(fc.receivedPackets)
	prometheus.MustRegister(fc.parsedRecords)
	prometheus.MustRegister(fc.droppedRecords)
	prometheus.MustRegister(fc.processingDuration)
	prometheus.MustRegister(fc.workerQueueLength)
}

func (fc *FlowCollector) getGeoInfo(ip net.IP) (country, city string, asn uint32, asOrg string) {
	if ip == nil || ip.IsUnspecified() {
		return "", "", 0, ""
	}

	ipStr := ip.String()

	// Check cache first
	if cached, ok := fc.geoCache.Load(ipStr); ok {
		entry := cached.(GeoIPEntry)
		if time.Now().Before(entry.Expiry) {
			return entry.Country, entry.City, entry.ASN, entry.ASOrg
		}
		fc.geoCache.Delete(ipStr)
	}

	// Query GeoIP database
	if fc.geoipDB != nil {
		if record, err := fc.geoipDB.City(ip); err == nil {
			if record.Country.IsoCode != "" {
				country = record.Country.IsoCode
			}
			if record.City.Names["en"] != "" {
				city = record.City.Names["en"]
			}
		}
	}

	// Query ASN database
	if fc.asnDB != nil {
		if record, err := fc.asnDB.ASN(ip); err == nil {
			asn = uint32(record.AutonomousSystemNumber)
			asOrg = record.AutonomousSystemOrganization
		}
	}

	// Cache the result
	cacheTTL := 1 * time.Hour
	if fc.config.GeoIP.CacheTTL != "" {
		if duration, err := time.ParseDuration(fc.config.GeoIP.CacheTTL); err == nil {
			cacheTTL = duration
		}
	}

	entry := GeoIPEntry{
		Country: country,
		City:    city,
		ASN:     asn,
		ASOrg:   asOrg,
		Expiry:  time.Now().Add(cacheTTL),
	}
	fc.geoCache.Store(ipStr, entry)

	// Enforce cache size limit (LRU approximation via random eviction)
	var count int
	fc.geoCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count > fc.config.GeoIP.CacheSize {
		// Trigger cleanup of expired entries
		now := time.Now()
		fc.geoCache.Range(func(key, value interface{}) bool {
			if value.(GeoIPEntry).Expiry.Before(now) {
				fc.geoCache.Delete(key)
			}
			return true
		})
	}

	return country, city, asn, asOrg
}

func (fc *FlowCollector) buildLabels(flow FlowRecord) prometheus.Labels {
	labels := prometheus.Labels{
		"protocol": strconv.Itoa(int(flow.Protocol)),
	}

	// Add dimensional labels
	for _, dim := range fc.config.Metrics.Labels.Dimensions {
		switch dim {
		case "src_port":
			labels["src_port"] = strconv.Itoa(int(flow.SrcPort))
		case "dst_port":
			labels["dst_port"] = strconv.Itoa(int(flow.DstPort))
		case "input_iface":
			labels["input_iface"] = strconv.Itoa(int(flow.InputIface))
		case "output_iface":
			labels["output_iface"] = strconv.Itoa(int(flow.OutputIface))
		}
	}

	// Add GeoIP labels
	if fc.config.Metrics.Labels.EnableGeoIP {
		srcCountry, _, _, _ := fc.getGeoInfo(flow.SrcAddr)
		dstCountry, _, _, _ := fc.getGeoInfo(flow.DstAddr)
		labels["src_country"] = srcCountry
		labels["dst_country"] = dstCountry
	}

	// Add ASN labels
	if fc.config.Metrics.Labels.EnableASN {
		_, _, srcASN, _ := fc.getGeoInfo(flow.SrcAddr)
		_, _, dstASN, _ := fc.getGeoInfo(flow.DstAddr)
		if srcASN > 0 {
			labels["src_asn"] = fmt.Sprintf("AS%d", srcASN)
		}
		if dstASN > 0 {
			labels["dst_asn"] = fmt.Sprintf("AS%d", dstASN)
		}
	}

	return labels
}

func (fc *FlowCollector) processFlow(flow FlowRecord) {
	start := time.Now()
	defer func() {
		fc.processingDuration.Observe(time.Since(start).Seconds())
	}()

	labels := fc.buildLabels(flow)

	fc.flowsTotal.With(labels).Inc()
	fc.bytesTotal.With(labels).Add(float64(flow.Bytes))
	fc.packetsTotal.With(labels).Add(float64(flow.Packets))

	fc.parsedRecords.Inc()

	// Update bandwidth metrics
	duration := flow.LastSeen.Sub(flow.FirstSeen).Seconds()
	if duration > 0 {
		bps := float64(flow.Bytes*8) / duration
		if flow.InputIface > 0 {
			fc.bandwidthGauge.WithLabelValues("in", strconv.Itoa(int(flow.InputIface))).Set(bps)
		}
		if flow.OutputIface > 0 {
			fc.bandwidthGauge.WithLabelValues("out", strconv.Itoa(int(flow.OutputIface))).Set(bps)
		}
	}

	// Aggregate flows
	fc.aggregateFlow(flow)
}

func (fc *FlowCollector) aggregateFlow(flow FlowRecord) {
	key := FlowKey{
		SrcAddr:     flow.SrcAddr.String(),
		DstAddr:     flow.DstAddr.String(),
		SrcPort:     flow.SrcPort,
		DstPort:     flow.DstPort,
		Protocol:    flow.Protocol,
		InputIface:  flow.InputIface,
		OutputIface: flow.OutputIface,
	}

	for _, window := range fc.config.Aggregation.TimeWindows {
		fc.timeWindowMutexes[window].Lock()
		m := fc.aggregatedFlows[window]
		if existing, ok := m[key]; ok {
			existing.Bytes += flow.Bytes
			existing.Packets += flow.Packets
			existing.Flows++
			if flow.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = flow.FirstSeen
			}
			if flow.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = flow.LastSeen
			}
			m[key] = existing
		} else {
			m[key] = AggregatedFlow{
				Bytes:     flow.Bytes,
				Packets:   flow.Packets,
				Flows:     1,
				FirstSeen: flow.FirstSeen,
				LastSeen:  flow.LastSeen,
			}
		}
		fc.timeWindowMutexes[window].Unlock()
	}
}

func (fc *FlowCollector) parseNetFlowV9(data []byte, addr *net.UDPAddr) []FlowRecord {
	if len(data) < 20 {
		fc.droppedRecords.Inc()
		return nil
	}

	reader := bytes.NewReader(data)
	var header NetFlowV9Header

	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		fc.droppedRecords.Inc()
		return nil
	}

	if header.Version != NETFLOW_V9 {
		fc.droppedRecords.Inc()
		return nil
	}

	var flows []FlowRecord
	exportTime := time.Unix(int64(header.UnixSecs), 0)

	for {
		if reader.Len() < 4 {
			break
		}
		var flowSet NetFlowV9FlowSet
		if err := binary.Read(reader, binary.BigEndian, &flowSet); err != nil {
			break
		}

		if flowSet.Length < 4 {
			break
		}

		setData := make([]byte, flowSet.Length-4)
		if _, err := reader.Read(setData); err != nil {
			break
		}

		if flowSet.FlowSetID == 0 {
			// Template flowset
			continue
		} else if flowSet.FlowSetID == 1 {
			// Options template - skip
			continue
		} else if flowSet.FlowSetID >= 256 {
			// Data flowset
			for len(setData) >= 48 {
				flow := FlowRecord{
					FirstSeen: exportTime,
					LastSeen:  exportTime,
				}

				// Parse basic fields (this is simplified; real implementation needs template)
				if len(setData) >= 16 {
					flow.SrcAddr = net.IP(setData[0:4]).To4()
					flow.DstAddr = net.IP(setData[4:8]).To4()
					flow.NextHop = net.IP(setData[8:12]).To4()
					flow.InputIface = binary.BigEndian.Uint32(setData[12:16])
				}
				if len(setData) >= 24 {
					flow.OutputIface = binary.BigEndian.Uint32(setData[16:20])
					flow.Packets = uint64(binary.BigEndian.Uint32(setData[20:24]))
				}
				if len(setData) >= 28 {
					flow.Bytes = uint64(binary.BigEndian.Uint32(setData[24:28]))
				}
				if len(setData) >= 32 {
					flow.FirstSeen = exportTime.Add(time.Duration(binary.BigEndian.Uint32(setData[28:32])) * time.Millisecond)
				}
				if len(setData) >= 36 {
					flow.LastSeen = exportTime.Add(time.Duration(binary.BigEndian.Uint32(setData[32:36])) * time.Millisecond)
				}
				if len(setData) >= 40 {
					flow.SrcPort = binary.BigEndian.Uint16(setData[36:38])
					flow.DstPort = binary.BigEndian.Uint16(setData[38:40])
				}
				if len(setData) >= 41 {
					flow.Protocol = setData[40]
				}

				flows = append(flows, flow)
				setData = setData[48:]
			}
		}
	}

	return flows
}

func (fc *FlowCollector) parseIPFIX(data []byte, addr *net.UDPAddr) []FlowRecord {
	if len(data) < 16 {
		fc.droppedRecords.Inc()
		return nil
	}

	reader := bytes.NewReader(data)
	var header IPFIXHeader

	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		fc.droppedRecords.Inc()
		return nil
	}

	if header.Version != IPFIX_V10 {
		fc.droppedRecords.Inc()
		return nil
	}

	var flows []FlowRecord
	exportTime := time.Unix(int64(header.ExportTime), 0)

	for {
		if reader.Len() < 4 {
			break
		}
		setID := binary.BigEndian.Uint16(data[reader.Offset : reader.Offset+2])
		length := binary.BigEndian.Uint16(data[reader.Offset+2 : reader.Offset+4])

		if length < 4 || int(length) > reader.Len() {
			break
		}

		setData := data[reader.Offset+4 : reader.Offset+length]
		reader.Seek(int64(length), io.SeekCurrent)

		if setID >= 256 {
			// Data set
			for len(setData) >= 32 {
				flow := FlowRecord{
					FirstSeen: exportTime,
					LastSeen:  exportTime,
				}

				if len(setData) >= 16 {
					flow.SrcAddr = net.IP(setData[0:4]).To4()
					flow.DstAddr = net.IP(setData[4:8]).To4()
				}
				if len(setData) >= 24 {
					flow.Bytes = uint64(binary.BigEndian.Uint32(setData[16:20]))
					flow.Packets = uint64(binary.BigEndian.Uint32(setData[20:24]))
				}
				if len(setData) >= 25 {
					flow.Protocol = setData[24]
				}
				if len(setData) >= 27 {
					flow.SrcPort = binary.BigEndian.Uint16(setData[25:27])
					flow.DstPort = binary.BigEndian.Uint16(setData[27:29])
				}

				flows = append(flows, flow)
				setData = setData[32:]
			}
		}
	}

	return flows
}

func (fc *FlowCollector) parseSFlow(data []byte, addr *net.UDPAddr) []FlowRecord {
	if len(data) < 28 {
		fc.droppedRecords.Inc()
		return nil
	}

	reader := bytes.NewReader(data)
	var header SFlowHeader

	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		fc.droppedRecords.Inc()
		return nil
	}

	if header.Version != SFLOW_V5 {
		fc.droppedRecords.Inc()
		return nil
	}

	var flows []FlowRecord
	baseTime := time.Unix(int64(header.SysUptime)/1000, 0)

	for i := 0; i < int(header.NumSamples); i++ {
		if reader.Len() < 4 {
			break
		}
		sampleType := binary.BigEndian.Uint32(data[reader.Offset : reader.Offset+4])

		if sampleType == SFLOW_FLOW_SAMPLE || sampleType == SFLOW_EXPANDED_SAMPLE {
			if reader.Len() < 28 {
				break
			}
			var fs SFlowFlowSample
			binary.Read(reader, binary.BigEndian, &fs)

			if reader.Len() < int(fs.NumRecords)*8 {
				break
			}

			for j := 0; j < int(fs.NumRecords); j++ {
				recordType := binary.BigEndian.Uint32(data[reader.Offset : reader.Offset+4])
				recordLength := binary.BigEndian.Uint32(data[reader.Offset+4 : reader.Offset+8])
				reader.Seek(8, io.SeekCurrent)

				if recordType == 1 && recordLength >= 40 { // Raw packet
					flow := FlowRecord{
						FirstSeen:      baseTime,
						LastSeen:       baseTime,
						InputIface:     fs.InputInterface,
						OutputInterface: fs.OutputInterface,
						Packets:        1,
						Bytes:          1500, // estimate
					}
					flows = append(flows, flow)
				}
				reader.Seek(int64(recordLength), io.SeekCurrent)
			}
		} else {
			// Skip unknown sample
			if reader.Len() < 4 {
				break
			}
			length := binary.BigEndian.Uint32(data[reader.Offset+4 : reader.Offset+8])
			reader.Seek(int64(length), io.SeekCurrent)
		}
	}

	return flows
}

func (fc *FlowCollector) handleUDPConnection(conn *net.UDPConn, protocol string) {
	defer fc.wg.Done()

	buffer := make([]byte, fc.config.Server.ReadBufferSize)

	for {
		select {
		case <-fc.stopChan:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if !strings.Contains(err.Error(), "use of closed network connection") {
					fc.logger.Error("UDP read error", "error", err, "protocol", protocol, "remote", addr)
				}
				continue
			}

			fc.receivedPackets.Inc()

			data := make([]byte, n)
			copy(data, buffer[:n])

			var flows []FlowRecord
			switch protocol {
			case "netflow":
				flows = fc.parseNetFlowV9(data, addr)
			case "ipfix":
				flows = fc.parseIPFIX(data, addr)
			case "sflow":
				flows = fc.parseSFlow(data, addr)
			}

			for _, flow := range flows {
				if flow.SrcAddr == nil || flow.DstAddr == nil {
					continue
				}
				select {
				case fc.flowChan <- flow:
				case <-fc.stopChan:
					return
				default:
					fc.droppedRecords.Inc()
				}
			}
		}
	}
}

func (fc *FlowCollector) startWorkers() {
	for i := 0; i < fc.config.Server.Workers; i++ {
		fc.wg.Add(1)
		go func() {
			defer fc.wg.Done()

			for {
				select {
				case flow := <-fc.flowChan:
					fc.processFlow(flow)
				case <-fc.stopChan:
					return
				}
			}
		}()
	}
}

func (fc *FlowCollector) updateQueueMetrics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fc.workerQueueLength.Set(float64(len(fc.flowChan)))
		case <-fc.stopChan:
			return
		}
	}
}

func (fc *FlowCollector) startAggregationCleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Hour)
			for window, mutex := range fc.timeWindowMutexes {
				mutex.Lock()
				m := fc.aggregatedFlows[window]
				for key, agg := range m {
					if agg.LastSeen.Before(cutoff) {
						delete(m, key)
					}
				}
				fc.aggregatedFlows[window] = m
				mutex.Unlock()
			}
		case <-fc.stopChan:
			return
		}
	}
}

func (fc *FlowCollector) Start() error {
	fc.logger.Info("Starting Flow Collector")

	// Start workers
	fc.startWorkers()

	// Start metric updaters
	go fc.updateQueueMetrics()
	go fc.startAggregationCleaner()

	// Start UDP listeners
	for _, listenAddr := range fc.config.Server.ListenAddresses {
		// NetFlow listener
		if fc.config.Server.Ports.NetFlow > 0 {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenAddr, fc.config.Server.Ports.NetFlow))
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return err
			}
			fc.logger.Info("Listening for NetFlow", "address", addr)
			fc.wg.Add(1)
			go fc.handleUDPConnection(conn, "netflow")
		}

		// IPFIX listener
		if fc.config.Server.Ports.IPFIX > 0 {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenAddr, fc.config.Server.Ports.IPFIX))
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return err
			}
			fc.logger.Info("Listening for IPFIX", "address", addr)
			fc.wg.Add(1)
			go fc.handleUDPConnection(conn, "ipfix")
		}

		// sFlow listener
		if fc.config.Server.Ports.SFlow > 0 {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenAddr, fc.config.Server.Ports.SFlow))
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return err
			}
			fc.logger.Info("Listening for sFlow", "address", addr)
			fc.wg.Add(1)
			go fc.handleUDPConnection(conn, "sflow")
		}
	}

	// Start metrics server
	go func() {
		http.Handle(fc.config.Server.MetricsPath, promhttp.Handler())
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>
            <head><title>Flow Collector</title></head>
            <body>
            <h1>Flow Collector</h1>
            <p><a href="` + fc.config.Server.MetricsPath + `">Metrics</a></p>
            </body>
            </html>`))
		})
		fc.logger.Info("Metrics server started", "port", fc.config.Server.MetricsPort, "path", fc.config.Server.MetricsPath)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", fc.config.Server.MetricsPort), nil); err != nil {
			fc.logger.Error("Metrics server failed", "error", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fc.logger.Info("Shutting down...")
	close(fc.stopChan)
	fc.wg.Wait()

	if fc.geoipDB != nil {
		fc.geoipDB.Close()
	}
	if fc.asnDB != nil {
		fc.asnDB.Close()
	}

	return nil
}

func main() {
	configFile := "config.yaml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Config file %s not found\n", configFile)
		os.Exit(1)
	}

	config, err := loadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	collector, err := NewFlowCollector(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create collector: %v\n", err)
		os.Exit(1)
	}

	if err := collector.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Collector failed: %v\n", err)
		os.Exit(1)
	}
}
