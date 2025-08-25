package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/netsampler/goflow2/decoders/netflow"
	"github.com/netsampler/goflow2/decoders/sflow"
	pb "github.com/netsampler/goflow2/pb"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// Config structures
type Config struct {
	Server struct {
		NetFlowPort int    `yaml:"netflow_port"`
		SFlowPort   int    `yaml:"sflow_port"`
		IPFIXPort   int    `yaml:"ipfix_port"`
		ListenAddr  string `yaml:"listen_addr"`
		MetricsPort int    `yaml:"metrics_port"`
		MetricsPath string `yaml:"metrics_path"`
	} `yaml:"server"`

	Performance struct {
		BufferSize  int `yaml:"buffer_size"`
		WorkerCount int `yaml:"worker_count"`
		BatchSize   int `yaml:"batch_size"`
		QueueSize   int `yaml:"queue_size"`
	} `yaml:"performance"`

	Aggregation struct {
		TimeWindows []string `yaml:"time_windows"`
		Dimensions  []string `yaml:"dimensions"`
	} `yaml:"aggregation"`

	Enrichment struct {
		GeoIPEnabled bool   `yaml:"geoip_enabled"`
		GeoIPPath    string `yaml:"geoip_path"`
		ASNEnabled   bool   `yaml:"asn_enabled"`
		ASNPath      string `yaml:"asn_path"`
		CacheSize    int    `yaml:"cache_size"`
	} `yaml:"enrichment"`

	Metrics struct {
		Namespace     string            `yaml:"namespace"`
		Subsystem     string            `yaml:"subsystem"`
		EnabledLabels []string          `yaml:"enabled_labels"`
		CustomLabels  map[string]string `yaml:"custom_labels"`
	} `yaml:"metrics"`

	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
}

// Flow record structure
type FlowRecord struct {
	SrcAddr    net.IP
	DstAddr    net.IP
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	InIf       uint32
	OutIf      uint32
	Bytes      uint64
	Packets    uint64
	StartTime  time.Time
	EndTime    time.Time
	SrcCountry string
	DstCountry string
	SrcASN     uint32
	DstASN     uint32
	SrcASNOrg  string
	DstASNOrg  string
}

// Aggregation key
type AggKey struct {
	SrcAddr    string
	DstAddr    string
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	InIf       uint32
	OutIf      uint32
	SrcCountry string
	DstCountry string
	SrcASN     uint32
	DstASN     uint32
}

// Aggregated metrics
type AggMetrics struct {
	Flows    uint64
	Bytes    uint64
	Packets  uint64
	LastSeen time.Time
}

// GeoIP and ASN cache entry
type EnrichmentEntry struct {
	Country   string
	City      string
	ASN       uint32
	ASNOrg    string
	Timestamp time.Time
}

// Collector main structure
type FlowCollector struct {
	config                *Config
	logger                *log.Logger
	geoipDB               *geoip2.Reader
	asnDB                 *geoip2.Reader
	enrichmentCache       sync.Map
	aggregations          map[string]map[AggKey]*AggMetrics
	aggMutex              sync.RWMutex
	netflowTemplateSystem netflow.NetFlowTemplateSystem

	// Prometheus metrics
	flowsTotal         *prometheus.CounterVec
	bytesTotal         *prometheus.CounterVec
	packetsTotal       *prometheus.CounterVec
	bandwidthBps       *prometheus.GaugeVec
	receivedPackets    prometheus.Counter
	parsedRecords      prometheus.Counter
	droppedRecords     prometheus.Counter
	processingDuration prometheus.Histogram
	workerQueueLength  prometheus.Gauge

	// Worker channels
	netflowChan chan []byte
	sflowChan   chan []byte
	ipfixChan   chan []byte
	recordChan  chan *FlowRecord

	// Internal counters
	receivedCount int64
	parsedCount   int64
	droppedCount  int64

	ctx    context.Context
	cancel context.CancelFunc
}

// Initialize collector
func NewFlowCollector(configPath string) (*FlowCollector, error) {
	// Load configuration
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logger
	logger := log.New(os.Stdout)
	level := log.InfoLevel
	switch strings.ToLower(config.Logging.Level) {
	case "debug":
		level = log.DebugLevel
	case "info":
		level = log.InfoLevel
	case "warn":
		level = log.WarnLevel
	case "error":
		level = log.ErrorLevel
	}
	logger.SetLevel(level)

	ctx, cancel := context.WithCancel(context.Background())

	collector := &FlowCollector{
		config:                config,
		logger:                logger,
		aggregations:          make(map[string]map[AggKey]*AggMetrics),
		netflowTemplateSystem: netflow.NetFlowTemplateSystem{}, // Initialize template system
		netflowChan:           make(chan []byte, config.Performance.QueueSize),
		sflowChan:             make(chan []byte, config.Performance.QueueSize),
		ipfixChan:             make(chan []byte, config.Performance.QueueSize),
		recordChan:            make(chan *FlowRecord, config.Performance.QueueSize*10),
		ctx:                   ctx,
		cancel:                cancel,
	}

	// Initialize aggregation windows
	for _, window := range config.Aggregation.TimeWindows {
		collector.aggregations[window] = make(map[AggKey]*AggMetrics)
	}

	// Setup GeoIP databases
	if err := collector.setupEnrichment(); err != nil {
		collector.logger.Warn("Failed to setup enrichment", "error", err)
	}

	// Setup Prometheus metrics
	collector.setupPrometheusMetrics()

	return collector, nil
}

// Load configuration from YAML
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
	if config.Server.ListenAddr == "" {
		config.Server.ListenAddr = "0.0.0.0"
	}
	if config.Server.MetricsPath == "" {
		config.Server.MetricsPath = "/metrics"
	}
	if config.Performance.BufferSize == 0 {
		config.Performance.BufferSize = 65536
	}
	if config.Performance.WorkerCount == 0 {
		config.Performance.WorkerCount = 4
	}
	if config.Performance.BatchSize == 0 {
		config.Performance.BatchSize = 100
	}
	if config.Performance.QueueSize == 0 {
		config.Performance.QueueSize = 1000
	}
	if config.Enrichment.CacheSize == 0 {
		config.Enrichment.CacheSize = 10000
	}
	if config.Metrics.Namespace == "" {
		config.Metrics.Namespace = "flow"
	}

	return &config, nil
}

// Setup GeoIP and ASN databases
func (fc *FlowCollector) setupEnrichment() error {
	if fc.config.Enrichment.GeoIPEnabled && fc.config.Enrichment.GeoIPPath != "" {
		db, err := geoip2.Open(fc.config.Enrichment.GeoIPPath)
		if err != nil {
			return fmt.Errorf("failed to open GeoIP database: %w", err)
		}
		fc.geoipDB = db
		fc.logger.Info("GeoIP database loaded", "path", fc.config.Enrichment.GeoIPPath)
	}

	if fc.config.Enrichment.ASNEnabled && fc.config.Enrichment.ASNPath != "" {
		db, err := geoip2.Open(fc.config.Enrichment.ASNPath)
		if err != nil {
			return fmt.Errorf("failed to open ASN database: %w", err)
		}
		fc.asnDB = db
		fc.logger.Info("ASN database loaded", "path", fc.config.Enrichment.ASNPath)
	}

	return nil
}

// Setup Prometheus metrics
func (fc *FlowCollector) setupPrometheusMetrics() {
	namespace := fc.config.Metrics.Namespace
	subsystem := fc.config.Metrics.Subsystem

	labelNames := []string{"src_addr", "dst_addr", "protocol"}
	if contains(fc.config.Metrics.EnabledLabels, "ports") {
		labelNames = append(labelNames, "src_port", "dst_port")
	}
	if contains(fc.config.Metrics.EnabledLabels, "interfaces") {
		labelNames = append(labelNames, "in_if", "out_if")
	}
	if contains(fc.config.Metrics.EnabledLabels, "geo") {
		labelNames = append(labelNames, "src_country", "dst_country")
	}
	if contains(fc.config.Metrics.EnabledLabels, "asn") {
		labelNames = append(labelNames, "src_asn", "dst_asn")
	}

	fc.flowsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "flows_total",
			Help:      "Total number of flows",
		},
		labelNames,
	)

	fc.bytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "bytes_total",
			Help:      "Total number of bytes",
		},
		labelNames,
	)

	fc.packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "packets_total",
			Help:      "Total number of packets",
		},
		labelNames,
	)

	fc.bandwidthBps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "bandwidth_bps",
			Help:      "Current bandwidth in bits per second",
		},
		labelNames,
	)

	fc.receivedPackets = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "received_packets_total",
			Help:      "Total number of received raw packets",
		},
	)

	fc.parsedRecords = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "parsed_records_total",
			Help:      "Total number of successfully parsed flow records",
		},
	)

	fc.droppedRecords = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "dropped_records_total",
			Help:      "Total number of dropped/failed records",
		},
	)

	fc.processingDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "processing_duration_seconds",
			Help:      "Time spent processing flow records",
			Buckets:   prometheus.DefBuckets,
		},
	)

	fc.workerQueueLength = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "worker_queue_length",
			Help:      "Current length of worker processing queue",
		},
	)

	// Register metrics
	prometheus.MustRegister(
		fc.flowsTotal,
		fc.bytesTotal,
		fc.packetsTotal,
		fc.bandwidthBps,
		fc.receivedPackets,
		fc.parsedRecords,
		fc.droppedRecords,
		fc.processingDuration,
		fc.workerQueueLength,
	)
}

// Start the collector
func (fc *FlowCollector) Start() error {
	fc.logger.Info("Starting flow collector")

	// Start UDP listeners
	go fc.startUDPListener("netflow", fc.config.Server.NetFlowPort, fc.netflowChan)
	go fc.startUDPListener("sflow", fc.config.Server.SFlowPort, fc.sflowChan)
	go fc.startUDPListener("ipfix", fc.config.Server.IPFIXPort, fc.ipfixChan)

	// Start protocol workers
	go fc.startNetFlowWorker()
	go fc.startSFlowWorker()
	go fc.startIPFIXWorker()

	// Start record processors
	for i := 0; i < fc.config.Performance.WorkerCount; i++ {
		go fc.recordProcessor()
	}

	// Start aggregation cleanup
	go fc.aggregationCleanup()

	// Start metrics updater
	go fc.metricsUpdater()

	// Start HTTP server for metrics
	go fc.startMetricsServer()

	return nil
}

// Start UDP listener
func (fc *FlowCollector) startUDPListener(protocol string, port int, ch chan<- []byte) {
	if port == 0 {
		fc.logger.Warn("Port not configured for protocol", "protocol", protocol)
		return
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", fc.config.Server.ListenAddr, port))
	if err != nil {
		fc.logger.Error("Failed to resolve UDP address", "protocol", protocol, "error", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fc.logger.Error("Failed to listen on UDP", "protocol", protocol, "error", err)
		return
	}
	defer conn.Close()

	fc.logger.Info("UDP listener started", "protocol", protocol, "address", addr)

	buffer := make([]byte, fc.config.Performance.BufferSize)

	for {
		select {
		case <-fc.ctx.Done():
			return
		default:
			n, _, err := conn.ReadFromUDP(buffer)
			if err != nil {
				fc.logger.Error("UDP read error", "protocol", protocol, "error", err)
				continue
			}

			atomic.AddInt64(&fc.receivedCount, 1)
			fc.receivedPackets.Inc()

			// Copy data to avoid buffer reuse issues
			data := make([]byte, n)
			copy(data, buffer[:n])

			select {
			case ch <- data:
			default:
				atomic.AddInt64(&fc.droppedCount, 1)
				fc.droppedRecords.Inc()
				fc.logger.Warn("Channel full, dropping packet", "protocol", protocol)
			}
		}
	}
}

// NetFlow worker
func (fc *FlowCollector) startNetFlowWorker() {
	for {
		select {
		case <-fc.ctx.Done():
			return
		case data := <-fc.netflowChan:
			fc.processNetFlowPacket(data)
		}
	}
}

// SFlow worker
func (fc *FlowCollector) startSFlowWorker() {
	for {
		select {
		case <-fc.ctx.Done():
			return
		case data := <-fc.sflowChan:
			fc.processSFlowPacket(data)
		}
	}
}

// IPFIX worker
func (fc *FlowCollector) startIPFIXWorker() {
	for {
		select {
		case <-fc.ctx.Done():
			return
		case data := <-fc.ipfixChan:
			fc.processIPFIXPacket(data)
		}
	}
}

// Process NetFlow packet
func (fc *FlowCollector) processNetFlowPacket(data []byte) {
	start := time.Now()
	defer func() {
		fc.processingDuration.Observe(time.Since(start).Seconds())
	}()

	// Create bytes buffer for DecodeMessage
	buffer := bytes.NewBuffer(data)

	// Decode NetFlow packet with template system
	packet, err := netflow.DecodeMessage(buffer, fc.netflowTemplateSystem)
	if err != nil {
		fc.logger.Debug("Failed to decode NetFlow packet", "error", err)
		atomic.AddInt64(&fc.droppedCount, 1)
		fc.droppedRecords.Inc()
		return
	}

	// Convert to flow records
	records := fc.convertNetFlowToRecords(packet)
	for _, record := range records {
		select {
		case fc.recordChan <- record:
			atomic.AddInt64(&fc.parsedCount, 1)
			fc.parsedRecords.Inc()
		default:
			atomic.AddInt64(&fc.droppedCount, 1)
			fc.droppedRecords.Inc()
		}
	}
}

// Process SFlow packet
func (fc *FlowCollector) processSFlowPacket(data []byte) {
	start := time.Now()
	defer func() {
		fc.processingDuration.Observe(time.Since(start).Seconds())
	}()

	// Create bytes buffer for DecodeMessage
	buffer := bytes.NewBuffer(data)

	// Decode SFlow packet
	packet, err := sflow.DecodeMessage(buffer)
	if err != nil {
		fc.logger.Debug("Failed to decode SFlow packet", "error", err)
		atomic.AddInt64(&fc.droppedCount, 1)
		fc.droppedRecords.Inc()
		return
	}

	// Convert to flow records
	records := fc.convertSFlowToRecords(packet)
	for _, record := range records {
		select {
		case fc.recordChan <- record:
			atomic.AddInt64(&fc.parsedCount, 1)
			fc.parsedRecords.Inc()
		default:
			atomic.AddInt64(&fc.droppedCount, 1)
			fc.droppedRecords.Inc()
		}
	}
}

// Process IPFIX packet (using NetFlow decoder as IPFIX is similar)
func (fc *FlowCollector) processIPFIXPacket(data []byte) {
	start := time.Now()
	defer func() {
		fc.processingDuration.Observe(time.Since(start).Seconds())
	}()

	// Create bytes buffer for DecodeMessage
	buffer := bytes.NewBuffer(data)

	// Decode IPFIX packet (using NetFlow decoder with template system)
	packet, err := netflow.DecodeMessage(buffer, fc.netflowTemplateSystem)
	if err != nil {
		fc.logger.Debug("Failed to decode IPFIX packet", "error", err)
		atomic.AddInt64(&fc.droppedCount, 1)
		fc.droppedRecords.Inc()
		return
	}

	// Convert to flow records
	records := fc.convertNetFlowToRecords(packet)
	for _, record := range records {
		select {
		case fc.recordChan <- record:
			atomic.AddInt64(&fc.parsedCount, 1)
			fc.parsedRecords.Inc()
		default:
			atomic.AddInt64(&fc.droppedCount, 1)
			fc.droppedRecords.Inc()
		}
	}
}

// Convert NetFlow to flow records
func (fc *FlowCollector) convertNetFlowToRecords(packet interface{}) []*FlowRecord {
	var records []*FlowRecord

	// Convert to protobuf flow message directly
	var flowMsg *pb.FlowMessage

	switch p := packet.(type) {
	case *netflow.NFv5Packet:
		flowMsg = fc.convertNFv5ToProtobuf(p)
	case *netflow.NFv9Packet:
		flowMsg = fc.convertNFv9ToProtobuf(p)
	case *netflow.IPFIXPacket:
		flowMsg = fc.convertIPFIXToProtobuf(p)
	default:
		fc.logger.Debug("Unsupported NetFlow packet type", "type", fmt.Sprintf("%T", packet))
		return records
	}

	if flowMsg == nil {
		return records
	}

	// Extract flow records from protobuf message
	for _, flow := range flowMsg.FlowData {
		record := fc.extractFlowRecordFromPB(flow)
		if record != nil {
			records = append(records, record)
		}
	}

	return records
}

// Convert SFlow to flow records
func (fc *FlowCollector) convertSFlowToRecords(packet interface{}) []*FlowRecord {
	var records []*FlowRecord

	// Convert to protobuf flow message directly
	var flowMsg *pb.FlowMessage

	switch p := packet.(type) {
	case *sflow.SFlowDatagram:
		flowMsg = fc.convertSFlowToProtobuf(p)
	default:
		fc.logger.Debug("Unsupported SFlow packet type", "type", fmt.Sprintf("%T", packet))
		return records
	}

	if flowMsg == nil {
		return records
	}

	// Extract flow records from protobuf message
	for _, flow := range flowMsg.FlowData {
		record := fc.extractFlowRecordFromPB(flow)
		if record != nil {
			records = append(records, record)
		}
	}

	return records
}

func (fc *FlowCollector) convertNFv5ToProtobuf(packet *netflow.NFv5Packet) *pb.FlowMessage {
	msg := &pb.FlowMessage{
		Type:      pb.FlowMessage_NETFLOW_V5,
		TimeRecv:  uint64(time.Now().Unix()),
		SamplerID: packet.Header.SourceId,
		FlowData:  make([]*pb.FlowData, len(packet.Records)),
	}

	for i, record := range packet.Records {
		msg.FlowData[i] = &pb.FlowData{
			SrcAddr:  record.SrcAddr,
			DstAddr:  record.DstAddr,
			NextHop:  record.NextHop,
			Input:    record.Input,
			Output:   record.Output,
			Packets:  uint64(record.DPkts),
			Octets:   uint64(record.DOctets),
			First:    uint64(record.First),
			Last:     uint64(record.Last),
			SrcPort:  uint32(record.SrcPort),
			DstPort:  uint32(record.DstPort),
			Proto:    uint32(record.Proto),
			TCPFlags: uint32(record.TCPFlags),
			Tos:      uint32(record.Tos),
			SrcAS:    record.SrcAS,
			DstAS:    record.DstAS,
			SrcMask:  uint32(record.SrcMask),
			DstMask:  uint32(record.DstMask),
		}
	}

	return msg
}

// Helper function to convert NFv9 to protobuf
func (fc *FlowCollector) convertNFv9ToProtobuf(packet *netflow.NFv9Packet) *pb.FlowMessage {
	msg := &pb.FlowMessage{
		Type:      pb.FlowMessage_NETFLOW_V9,
		TimeRecv:  uint64(time.Now().Unix()),
		SamplerID: packet.Header.SourceId,
		FlowData:  make([]*pb.FlowData, 0),
	}

	for _, flowSet := range packet.FlowSets {
		if dataFlowSet, ok := flowSet.(*netflow.NFv9DataFlowSet); ok {
			for _, record := range dataFlowSet.Records {
				flowData := &pb.FlowData{}
				fc.mapNFv9RecordToFlowData(record, flowData)
				msg.FlowData = append(msg.FlowData, flowData)
			}
		}
	}

	return msg
}

// Helper function to convert IPFIX to protobuf
func (fc *FlowCollector) convertIPFIXToProtobuf(packet *netflow.IPFIXPacket) *pb.FlowMessage {
	msg := &pb.FlowMessage{
		Type:      pb.FlowMessage_IPFIX,
		TimeRecv:  uint64(time.Now().Unix()),
		SamplerID: packet.Header.ObservationDomainId,
		FlowData:  make([]*pb.FlowData, 0),
	}

	for _, flowSet := range packet.FlowSets {
		if dataFlowSet, ok := flowSet.(*netflow.IPFIXDataFlowSet); ok {
			for _, record := range dataFlowSet.Records {
				flowData := &pb.FlowData{}
				fc.mapIPFIXRecordToFlowData(record, flowData)
				msg.FlowData = append(msg.FlowData, flowData)
			}
		}
	}

	return msg
}

// Helper function to convert SFlow to protobuf
func (fc *FlowCollector) convertSFlowToProtobuf(packet *sflow.SFlowDatagram) *pb.FlowMessage {
	msg := &pb.FlowMessage{
		Type:      pb.FlowMessage_SFLOW_5,
		TimeRecv:  uint64(time.Now().Unix()),
		SamplerID: packet.AgentId,
		FlowData:  make([]*pb.FlowData, 0),
	}

	for _, sample := range packet.Samples {
		if flowSample, ok := sample.(*sflow.FlowSample); ok {
			for _, record := range flowSample.Records {
				if flowRecord, ok := record.(*sflow.RawPacketFlowRecord); ok {
					flowData := &pb.FlowData{}
					fc.mapSFlowRecordToFlowData(flowRecord, flowData)
					msg.FlowData = append(msg.FlowData, flowData)
				}
			}
		}
	}

	return msg
}

// Helper functions to map records to flow data
func (fc *FlowCollector) mapNFv9RecordToFlowData(record netflow.NFv9Record, flowData *pb.FlowData) {
	// Map NFv9 fields to FlowData - this is a simplified mapping
	// You would need to implement proper field mapping based on NFv9 templates
	for fieldType, value := range record {
		switch fieldType {
		case 8: // IPV4_SRC_ADDR
			if addr, ok := value.(uint32); ok {
				flowData.SrcAddr = addr
			}
		case 12: // IPV4_DST_ADDR
			if addr, ok := value.(uint32); ok {
				flowData.DstAddr = addr
			}
		case 7: // L4_SRC_PORT
			if port, ok := value.(uint16); ok {
				flowData.SrcPort = uint32(port)
			}
		case 11: // L4_DST_PORT
			if port, ok := value.(uint16); ok {
				flowData.DstPort = uint32(port)
			}
		case 4: // PROTOCOL
			if proto, ok := value.(uint8); ok {
				flowData.Proto = uint32(proto)
			}
		case 2: // IN_PKTS
			if pkts, ok := value.(uint64); ok {
				flowData.Packets = pkts
			}
		case 1: // IN_BYTES
			if bytes, ok := value.(uint64); ok {
				flowData.Octets = bytes
			}
		}
	}
}

func (fc *FlowCollector) mapIPFIXRecordToFlowData(record netflow.IPFIXRecord, flowData *pb.FlowData) {
	// Similar to NFv9 but for IPFIX
	fc.mapNFv9RecordToFlowData(netflow.NFv9Record(record), flowData)
}

func (fc *FlowCollector) mapSFlowRecordToFlowData(record *sflow.RawPacketFlowRecord, flowData *pb.FlowData) {
	// Extract information from SFlow raw packet
	flowData.Packets = 1 // SFlow samples individual packets
	flowData.Octets = uint64(record.FrameLength)

	// You would need to parse the raw packet data to extract IP addresses, ports, etc.
	// This is a simplified implementation
}

// Extract flow record from protobuf
func (fc *FlowCollector) extractFlowRecordFromPB(flow *pb.FlowData) *FlowRecord {
	record := &FlowRecord{
		StartTime: time.Unix(int64(flow.First), 0),
		EndTime:   time.Unix(int64(flow.Last), 0),
		SrcPort:   uint16(flow.SrcPort),
		DstPort:   uint16(flow.DstPort),
		Protocol:  uint8(flow.Proto),
		InIf:      flow.Input,
		OutIf:     flow.Output,
		Bytes:     flow.Octets,
		Packets:   flow.Packets,
	}

	// Convert IP addresses
	record.SrcAddr = intToIP(flow.SrcAddr)
	record.DstAddr = intToIP(flow.DstAddr)

	// Validate required fields
	if record.SrcAddr == nil || record.DstAddr == nil {
		return nil
	}

	// Enrich with GeoIP and ASN data
	fc.enrichRecord(record)

	return record
}

// Helper function to convert uint32 IP to net.IP
func intToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// Extract flow record from parsed data
func (fc *FlowCollector) extractFlowRecord(flow map[string]interface{}) *FlowRecord {
	record := &FlowRecord{
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	// Extract basic flow information
	if srcAddr, ok := flow["src_addr"].(string); ok {
		record.SrcAddr = net.ParseIP(srcAddr)
	}
	if dstAddr, ok := flow["dst_addr"].(string); ok {
		record.DstAddr = net.ParseIP(dstAddr)
	}
	if srcPort, ok := flow["src_port"].(float64); ok {
		record.SrcPort = uint16(srcPort)
	}
	if dstPort, ok := flow["dst_port"].(float64); ok {
		record.DstPort = uint16(dstPort)
	}
	if proto, ok := flow["protocol"].(float64); ok {
		record.Protocol = uint8(proto)
	}
	if inIf, ok := flow["in_if"].(float64); ok {
		record.InIf = uint32(inIf)
	}
	if outIf, ok := flow["out_if"].(float64); ok {
		record.OutIf = uint32(outIf)
	}
	if bytes, ok := flow["bytes"].(float64); ok {
		record.Bytes = uint64(bytes)
	}
	if packets, ok := flow["packets"].(float64); ok {
		record.Packets = uint64(packets)
	}

	// Validate required fields
	if record.SrcAddr == nil || record.DstAddr == nil {
		return nil
	}

	// Enrich with GeoIP and ASN data
	fc.enrichRecord(record)

	return record
}

// Enrich record with GeoIP and ASN data
func (fc *FlowCollector) enrichRecord(record *FlowRecord) {
	// Check cache first
	srcKey := record.SrcAddr.String()
	dstKey := record.DstAddr.String()

	if entry, ok := fc.enrichmentCache.Load(srcKey); ok {
		if e, ok := entry.(*EnrichmentEntry); ok && time.Since(e.Timestamp) < time.Hour {
			record.SrcCountry = e.Country
			record.SrcASN = e.ASN
			record.SrcASNOrg = e.ASNOrg
		}
	} else {
		// Enrich source IP
		fc.enrichIP(record.SrcAddr, &record.SrcCountry, &record.SrcASN, &record.SrcASNOrg)
		fc.enrichmentCache.Store(srcKey, &EnrichmentEntry{
			Country:   record.SrcCountry,
			ASN:       record.SrcASN,
			ASNOrg:    record.SrcASNOrg,
			Timestamp: time.Now(),
		})
	}

	if entry, ok := fc.enrichmentCache.Load(dstKey); ok {
		if e, ok := entry.(*EnrichmentEntry); ok && time.Since(e.Timestamp) < time.Hour {
			record.DstCountry = e.Country
			record.DstASN = e.ASN
			record.DstASNOrg = e.ASNOrg
		}
	} else {
		// Enrich destination IP
		fc.enrichIP(record.DstAddr, &record.DstCountry, &record.DstASN, &record.DstASNOrg)
		fc.enrichmentCache.Store(dstKey, &EnrichmentEntry{
			Country:   record.DstCountry,
			ASN:       record.DstASN,
			ASNOrg:    record.DstASNOrg,
			Timestamp: time.Now(),
		})
	}
}

// Enrich IP with GeoIP and ASN data
func (fc *FlowCollector) enrichIP(ip net.IP, country *string, asn *uint32, asnOrg *string) {
	if fc.geoipDB != nil && fc.config.Enrichment.GeoIPEnabled {
		if record, err := fc.geoipDB.Country(ip); err == nil {
			*country = record.Country.IsoCode
		}
	}

	if fc.asnDB != nil && fc.config.Enrichment.ASNEnabled {
		if record, err := fc.asnDB.ASN(ip); err == nil {
			*asn = uint32(record.AutonomousSystemNumber)
			*asnOrg = record.AutonomousSystemOrganization
		}
	}
}

// Record processor
func (fc *FlowCollector) recordProcessor() {
	for {
		select {
		case <-fc.ctx.Done():
			return
		case record := <-fc.recordChan:
			fc.workerQueueLength.Set(float64(len(fc.recordChan)))
			fc.processFlowRecord(record)
		}
	}
}

// Process flow record and update aggregations
func (fc *FlowCollector) processFlowRecord(record *FlowRecord) {
	now := time.Now()

	// Create aggregation key
	key := fc.createAggregationKey(record)

	fc.aggMutex.Lock()
	defer fc.aggMutex.Unlock()

	// Update aggregations for each time window
	for _, window := range fc.config.Aggregation.TimeWindows {
		if agg, exists := fc.aggregations[window][key]; exists {
			agg.Flows++
			agg.Bytes += record.Bytes
			agg.Packets += record.Packets
			agg.LastSeen = now
		} else {
			fc.aggregations[window][key] = &AggMetrics{
				Flows:    1,
				Bytes:    record.Bytes,
				Packets:  record.Packets,
				LastSeen: now,
			}
		}
	}
}

// Create aggregation key based on configured dimensions
func (fc *FlowCollector) createAggregationKey(record *FlowRecord) AggKey {
	key := AggKey{
		Protocol: record.Protocol,
	}

	dimensions := fc.config.Aggregation.Dimensions

	if contains(dimensions, "src_addr") {
		key.SrcAddr = record.SrcAddr.String()
	}
	if contains(dimensions, "dst_addr") {
		key.DstAddr = record.DstAddr.String()
	}
	if contains(dimensions, "src_port") {
		key.SrcPort = record.SrcPort
	}
	if contains(dimensions, "dst_port") {
		key.DstPort = record.DstPort
	}
	if contains(dimensions, "in_if") {
		key.InIf = record.InIf
	}
	if contains(dimensions, "out_if") {
		key.OutIf = record.OutIf
	}
	if contains(dimensions, "src_country") {
		key.SrcCountry = record.SrcCountry
	}
	if contains(dimensions, "dst_country") {
		key.DstCountry = record.DstCountry
	}
	if contains(dimensions, "src_asn") {
		key.SrcASN = record.SrcASN
	}
	if contains(dimensions, "dst_asn") {
		key.DstASN = record.DstASN
	}

	return key
}

// Aggregation cleanup worker
func (fc *FlowCollector) aggregationCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-fc.ctx.Done():
			return
		case <-ticker.C:
			fc.cleanupExpiredAggregations()
		}
	}
}

// Clean up expired aggregations
func (fc *FlowCollector) cleanupExpiredAggregations() {
	now := time.Now()

	fc.aggMutex.Lock()
	defer fc.aggMutex.Unlock()

	for window, aggregations := range fc.aggregations {
		// Parse window duration
		windowDuration, err := parseTimeWindow(window)
		if err != nil {
			continue
		}

		// Remove expired aggregations
		for key, agg := range aggregations {
			if now.Sub(agg.LastSeen) > windowDuration*2 {
				delete(aggregations, key)
			}
		}
	}
}

// Parse time window string to duration
func parseTimeWindow(window string) (time.Duration, error) {
	switch window {
	case "1m":
		return time.Minute, nil
	case "5m":
		return 5 * time.Minute, nil
	case "15m":
		return 15 * time.Minute, nil
	case "1h":
		return time.Hour, nil
	case "1d":
		return 24 * time.Hour, nil
	default:
		return time.ParseDuration(window)
	}
}

// Metrics updater
func (fc *FlowCollector) metricsUpdater() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fc.ctx.Done():
			return
		case <-ticker.C:
			fc.updatePrometheusMetrics()
		}
	}
}

// Update Prometheus metrics from aggregations
func (fc *FlowCollector) updatePrometheusMetrics() {
	fc.aggMutex.RLock()
	defer fc.aggMutex.RUnlock()

	// Use the shortest time window for real-time metrics
	window := "1m"
	if len(fc.config.Aggregation.TimeWindows) > 0 {
		window = fc.config.Aggregation.TimeWindows[0]
	}

	aggregations, exists := fc.aggregations[window]
	if !exists {
		return
	}

	// Calculate bandwidth and update metrics
	windowDuration, err := parseTimeWindow(window)
	if err != nil {
		return
	}

	for key, agg := range aggregations {
		labels := fc.createPrometheusLabels(key)

		// Update counters (these are cumulative)
		fc.flowsTotal.With(labels).Add(float64(agg.Flows))
		fc.bytesTotal.With(labels).Add(float64(agg.Bytes))
		fc.packetsTotal.With(labels).Add(float64(agg.Packets))

		// Calculate bandwidth in bits per second
		bps := float64(agg.Bytes*8) / windowDuration.Seconds()
		fc.bandwidthBps.With(labels).Set(bps)

		// Reset aggregation after updating metrics
		agg.Flows = 0
		agg.Bytes = 0
		agg.Packets = 0
	}
}

// Create Prometheus labels from aggregation key
func (fc *FlowCollector) createPrometheusLabels(key AggKey) prometheus.Labels {
	labels := prometheus.Labels{
		"src_addr": key.SrcAddr,
		"dst_addr": key.DstAddr,
		"protocol": strconv.Itoa(int(key.Protocol)),
	}

	enabledLabels := fc.config.Metrics.EnabledLabels

	if contains(enabledLabels, "ports") {
		labels["src_port"] = strconv.Itoa(int(key.SrcPort))
		labels["dst_port"] = strconv.Itoa(int(key.DstPort))
	}
	if contains(enabledLabels, "interfaces") {
		labels["in_if"] = strconv.Itoa(int(key.InIf))
		labels["out_if"] = strconv.Itoa(int(key.OutIf))
	}
	if contains(enabledLabels, "geo") {
		labels["src_country"] = key.SrcCountry
		labels["dst_country"] = key.DstCountry
	}
	if contains(enabledLabels, "asn") {
		labels["src_asn"] = strconv.Itoa(int(key.SrcASN))
		labels["dst_asn"] = strconv.Itoa(int(key.DstASN))
	}

	// Add custom labels
	for k, v := range fc.config.Metrics.CustomLabels {
		labels[k] = v
	}

	return labels
}

// Start metrics HTTP server
func (fc *FlowCollector) startMetricsServer() {
	mux := http.NewServeMux()
	mux.Handle(fc.config.Server.MetricsPath, promhttp.Handler())
	mux.HandleFunc("/health", fc.healthCheck)
	mux.HandleFunc("/status", fc.statusHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", fc.config.Server.MetricsPort),
		Handler: mux,
	}

	fc.logger.Info("Metrics server started", "address", server.Addr, "path", fc.config.Server.MetricsPath)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fc.logger.Error("Metrics server error", "error", err)
	}
}

// Health check endpoint
func (fc *FlowCollector) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	status := map[string]interface{}{
		"status":           "healthy",
		"received_packets": atomic.LoadInt64(&fc.receivedCount),
		"parsed_records":   atomic.LoadInt64(&fc.parsedCount),
		"dropped_records":  atomic.LoadInt64(&fc.droppedCount),
		"timestamp":        time.Now().Unix(),
	}

	json.NewEncoder(w).Encode(status)
}

// Status endpoint
func (fc *FlowCollector) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	fc.aggMutex.RLock()
	aggStats := make(map[string]int)
	for window, aggregations := range fc.aggregations {
		aggStats[window] = len(aggregations)
	}
	fc.aggMutex.RUnlock()

	// Get cache size
	cacheSize := 0
	fc.enrichmentCache.Range(func(key, value interface{}) bool {
		cacheSize++
		return true
	})

	status := map[string]interface{}{
		"status":                "running",
		"received_packets":      atomic.LoadInt64(&fc.receivedCount),
		"parsed_records":        atomic.LoadInt64(&fc.parsedCount),
		"dropped_records":       atomic.LoadInt64(&fc.droppedCount),
		"aggregation_counts":    aggStats,
		"enrichment_cache_size": cacheSize,
		"queue_lengths": map[string]int{
			"netflow": len(fc.netflowChan),
			"sflow":   len(fc.sflowChan),
			"ipfix":   len(fc.ipfixChan),
			"records": len(fc.recordChan),
		},
		"config":    fc.config,
		"timestamp": time.Now().Unix(),
	}

	json.NewEncoder(w).Encode(status)
}

// Stop the collector
func (fc *FlowCollector) Stop() {
	fc.logger.Info("Stopping flow collector")
	fc.cancel()

	// Close databases
	if fc.geoipDB != nil {
		fc.geoipDB.Close()
	}
	if fc.asnDB != nil {
		fc.asnDB.Close()
	}
}

// Utility function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Main function
func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatal("Configuration file not found", "path", configPath)
	}

	// Create collector
	collector, err := NewFlowCollector(configPath)
	if err != nil {
		log.Fatal("Failed to create collector", "error", err)
	}
	defer collector.Stop()

	// Start collector
	if err := collector.Start(); err != nil {
		log.Fatal("Failed to start collector", "error", err)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigChan
	collector.logger.Info("Received signal, shutting down", "signal", sig)

	// Graceful shutdown
	collector.Stop()
	time.Sleep(2 * time.Second)
}
