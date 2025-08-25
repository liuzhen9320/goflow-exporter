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
	Version        uint16
	Length         uint16
	ExportTime     uint32
	SequenceNum    uint32
	ObservationDomainID uint32
}

// sFlow structures
type SFlowHeader struct {
	Version        uint32
	AddressType    uint32
	AgentAddress   uint32
	SubAgentID     uint32
	SequenceNum    uint32
	SysUptime      uint32
	NumSamples     uint32
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
	aggregatedFlows sync.Map
	aggregationMutex sync.RWMutex
	
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
		config.Server.ReadBufferSize = 4096
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
	if len(config.Aggregation.TimeWindows) == 0 {
		config.Aggregation.TimeWindows = []string{"1m", "5m", "15m", "1h"}
	}
	
	return &config, nil
}

func NewFlowCollector(config *Config) (*FlowCollector, error) {
	logger := log.New(os.Stdout)
	
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
		config:   config,
		logger:   logger,
		flowChan: make(chan FlowRecord, config.Server.BatchSize*10),
		stopChan: make(chan struct{}),
	}
	
	// Initialize GeoIP databases
	if config.Metrics.Labels.EnableGeoIP && config.GeoIP.DatabasePath != "" {
		db, err := geoip2.Open(config.GeoIP.DatabasePath)
		if err != nil {
			logger.Warn("Failed to open GeoIP database", "error", err)
		} else {
			collector.geoipDB = db
			logger.Info("GeoIP database loaded", "path", config.GeoIP.DatabasePath)
		}
	}
	
	if config.Metrics.Labels.EnableASN && config.GeoIP.ASNDatabasePath != "" {
		db, err := geoip2.Open(config.GeoIP.ASNDatabasePath)
		if err != nil {
			logger.Warn("Failed to open ASN database", "error", err)
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
	for _, dim := range fc.config.Metrics.Labels.Dimensions {
		labels = append(labels, dim)
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
	if ip == nil {
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
			country = record.Country.IsoCode
			city = record.City.Names["en"]
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
		labels["src_asn"] = strconv.Itoa(int(srcASN))
		labels["dst_asn"] = strconv.Itoa(int(dstASN))
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
		fc.bandwidthGauge.WithLabelValues("input", strconv.Itoa(int(flow.InputIface))).Set(bps)
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
	
	fc.aggregationMutex.Lock()
	defer fc.aggregationMutex.Unlock()
	
	if existing, ok := fc.aggregatedFlows.Load(key); ok {
		agg := existing.(AggregatedFlow)
		agg.Bytes += flow.Bytes
		agg.Packets += flow.Packets
		agg.Flows++
		if flow.FirstSeen.Before(agg.FirstSeen) {
			agg.FirstSeen = flow.FirstSeen
		}
		if flow.LastSeen.After(agg.LastSeen) {
			agg.LastSeen = flow.LastSeen
		}
		fc.aggregatedFlows.Store(key, agg)
	} else {
		fc.aggregatedFlows.Store(key, AggregatedFlow{
			Bytes:     flow.Bytes,
			Packets:   flow.Packets,
			Flows:     1,
			FirstSeen: flow.FirstSeen,
			LastSeen:  flow.LastSeen,
		})
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
	timestamp := time.Unix(int64(header.UnixSecs), 0)
	
	for i := 0; i < int(header.Count); i++ {
		var flowSet NetFlowV9FlowSet
		if err := binary.Read(reader, binary.BigEndian, &flowSet); err != nil {
			break
		}
		
		if flowSet.FlowSetID == 0 || flowSet.FlowSetID == 1 {
			// Template FlowSet - skip for now
			reader.Seek(int64(flowSet.Length-4), io.SeekCurrent)
			continue
		}
		
		// Data FlowSet
		flowData := make([]byte, flowSet.Length-4)
		if _, err := reader.Read(flowData); err != nil {
			break
		}
		
		// Simple parsing for common fields
		if len(flowData) >= 48 {
			flow := FlowRecord{
				FirstSeen: timestamp,
				LastSeen:  timestamp,
			}
			
			// Extract common fields (simplified)
			if len(flowData) >= 4 {
				flow.SrcAddr = net.IP(flowData[0:4])
			}
			if len(flowData) >= 8 {
				flow.DstAddr = net.IP(flowData[4:8])
			}
			if len(flowData) >= 10 {
				flow.SrcPort = binary.BigEndian.Uint16(flowData[8:10])
			}
			if len(flowData) >= 12 {
				flow.DstPort = binary.BigEndian.Uint16(flowData[10:12])
			}
			if len(flowData) >= 13 {
				flow.Protocol = flowData[12]
			}
			if len(flowData) >= 21 {
				flow.Bytes = uint64(binary.BigEndian.Uint32(flowData[13:17]))
				flow.Packets = uint64(binary.BigEndian.Uint32(flowData[17:21]))
			}
			
			flows = append(flows, flow)
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
	timestamp := time.Unix(int64(header.ExportTime), 0)
	
	// Simplified IPFIX parsing
	remaining := data[16:]
	for len(remaining) >= 4 {
		setID := binary.BigEndian.Uint16(remaining[0:2])
		length := binary.BigEndian.Uint16(remaining[2:4])
		
		if length < 4 || int(length) > len(remaining) {
			break
		}
		
		if setID >= 256 {
			// Data Set
			setData := remaining[4:length]
			
			// Simple record parsing
			if len(setData) >= 48 {
				flow := FlowRecord{
					FirstSeen: timestamp,
					LastSeen:  timestamp,
				}
				
				// Extract basic fields (simplified)
				if len(setData) >= 4 {
					flow.SrcAddr = net.IP(setData[0:4])
				}
				if len(setData) >= 8 {
					flow.DstAddr = net.IP(setData[4:8])
				}
				if len(setData) >= 10 {
					flow.SrcPort = binary.BigEndian.Uint16(setData[8:10])
				}
				if len(setData) >= 12 {
					flow.DstPort = binary.BigEndian.Uint16(setData[10:12])
				}
				if len(setData) >= 13 {
					flow.Protocol = setData[12]
				}
				if len(setData) >= 21 {
					flow.Bytes = uint64(binary.BigEndian.Uint32(setData[13:17]))
					flow.Packets = uint64(binary.BigEndian.Uint32(setData[17:21]))
				}
				
				flows = append(flows, flow)
			}
		}
		
		remaining = remaining[length:]
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
	timestamp := time.Now()
	
	// Simplified sFlow parsing
	for i := 0; i < int(header.NumSamples); i++ {
		if reader.Len() < 8 {
			break
		}
		
		var sampleType, sampleLength uint32
		binary.Read(reader, binary.BigEndian, &sampleType)
		binary.Read(reader, binary.BigEndian, &sampleLength)
		
		if sampleLength < 8 || int(sampleLength) > reader.Len() {
			break
		}
		
		sampleData := make([]byte, sampleLength-8)
		if _, err := reader.Read(sampleData); err != nil {
			break
		}
		
		// Parse flow sample (simplified)
		if sampleType == 1 && len(sampleData) >= 24 {
			flow := FlowRecord{
				FirstSeen: timestamp,
				LastSeen:  timestamp,
			}
			
			// Extract basic information from sFlow sample
			sampleReader := bytes.NewReader(sampleData)
			var sequenceNum, sourceID, samplingRate, samplePool uint32
			binary.Read(sampleReader, binary.BigEndian, &sequenceNum)
			binary.Read(sampleReader, binary.BigEndian, &sourceID)
			binary.Read(sampleReader, binary.BigEndian, &samplingRate)
			binary.Read(sampleReader, binary.BigEndian, &samplePool)
			
			flow.InputIface = sourceID
			flow.Bytes = uint64(samplingRate * 1500) // Estimate
			flow.Packets = 1
			
			flows = append(flows, flow)
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
					fc.logger.Error("UDP read error", "error", err, "protocol", protocol)
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
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-1 * time.Hour)
			fc.aggregatedFlows.Range(func(key, value interface{}) bool {
				agg := value.(AggregatedFlow)
				if agg.LastSeen.Before(cutoff) {
					fc.aggregatedFlows.Delete(key)
				}
				return true
			})
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
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listen
