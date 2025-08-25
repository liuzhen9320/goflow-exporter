# goflow-exporter

使用 Golang 编写一个网络流收集器，支持 Netflow v9/IPFIX/sFlow 协议，将路由器流量数据聚合为 Prometheus 指标供 Grafana 展示和告警。

1. 使用 `netsampler/goflow2` 库作为核心流处理引擎，支持 NetFlow v9、IPFIX 和 sFlow 协议的解析，并将不同协议的数据统一转换为标准化内部格式。
2. 建立多端口监听服务架构，为 NetFlow、sFlow、IPFIX 分别配置独立 UDP 监听端口，实现按端口区分协议的并发接入。
3. 支持 IPv4 和 IPv6 双栈监听，允许配置监听地址和绑定特定网络接口，适配多网卡环境。
4. 实现健壮的流数据接收模块，处理大包、分片 UDP 数据报，具备基本的数据完整性校验能力。
5. 采用 YAML 格式设计配置文件系统，涵盖服务器设置、性能参数、指标选项、增强功能开关等所有可调参数。
6. 支持嵌套结构和数组配置，满足复杂部署场景需求（如多监听地址、多维度标签配置）。
7. 提供灵活的日志级别配置（debug/info/warn/error），支持结构化日志输出。
8. 可配置输入缓冲区大小、工作线程数、批处理大小等性能相关参数，便于根据硬件资源调整处理能力。
9. 设计基于 goroutine 的高并发处理系统，使用 worker pool 模式处理海量并发流数据。
10. 通过 channel 实现生产者-消费者模式，解耦接收与处理流程，保障系统稳定性与吞吐能力。
11. 建立统一的数据解析与标准化流程，对 goflow2 输出的流记录进行清洗、字段归一化和基础验证，确保数据质量。
12. 开发内存高效的数据聚合算法，支持基于时间窗口的统计（如 1m、5m、15m、1h），防止内存无限增长。
13. 构建时间窗口聚合机制，支持多种粒度并行计算，使用定时刷新策略更新聚合结果。
14. 设计多维度聚合引擎，支持按源 IP、目标 IP、源端口、目的端口、协议类型、输入接口等维度进行分组统计。
15. 允许通过配置定义聚合维度组合，支持常用维度的灵活启用与标签生成。
16. 实现标准 Prometheus 指标导出功能，设计清晰的命名规范（如 `flow_bytes_total`, `flow_packets_total`）和标签体系（如 `src_country`, `dst_asn`）。
17. 支持指标命名空间（namespace）和子系统（subsystem）配置，避免与其他服务指标冲突。
18. 暴露基础流量指标：
   - `flow_flows_total`（流数量）
   - `flow_bytes_total`（字节数）
   - `flow_packets_total`（包数量）
   支持累计计数，供 PromQL 计算速率。
19. 提供带宽利用率相关指标（如 `flow_bandwidth_bps`），按接口或 IP 维度暴露瞬时速率，用于计算入向/出向带宽使用情况。
20. 集成 GeoIP 地理位置查询功能，支持 MaxMind GeoIP2 数据库，可查询 IP 地址对应的国家、城市、经纬度信息。
21. 实现 ASN（自治系统号）查询功能，识别 IP 所属的 AS 编号及组织名称（如 AS15169 - Google）。
22. 对 GeoIP 和 ASN 查询结果实现本地缓存机制，减少重复查表开销，提升处理性能。
23. 支持数据库热加载或定期更新提示，确保地理位置与 ASN 数据时效性（不在代码里留更新或下载逻辑，由外部程序下载解压）
24. 在 Prometheus 指标中添加可选标签，如 `src_country`, `dst_country`, `src_asn`, `dst_asn`，由配置控制是否启用。
25. 暴露系统内部运行指标，用于监控 exporter 健康状态：
   - `flow_received_packets_total`（收到的原始数据包）
   - `flow_parsed_records_total`（成功解析的流记录数）
   - `flow_dropped_records_total`（丢弃/解析失败数）
   - `flow_processing_duration_seconds`（处理延迟）
   - `flow_worker_queue_length`（处理队列长度）
26. 构建轻量高性能 HTTP 服务器，暴露 `/metrics` 端点，返回标准 Prometheus 文本格式。
27. 实现指标的实时更新机制，无需复杂缓存，保证 Prometheus 抓取时获取最新聚合值。
28. 建立基础错误处理机制，对网络异常、解析失败、内存压力等情况记录日志并继续运行，保障服务持续可用。
29. 集成 `charmbracelet/log` 作为统一日志组件，支持结构化日志输出，便于调试与运维排查。
30. 将所有代码放入一个 main.go 里，所有上述要求必需完整实现，不得留有 TODO；另外你只需要输出 main.go 和 config.yaml 和示例查询即可

---

# Flow Collector Configuration

```yaml
# Server configuration
server:
  # UDP listening ports for different protocols
  netflow_port: 2055      # NetFlow v9 port
  sflow_port: 6343        # sFlow port  
  ipfix_port: 4739        # IPFIX port
  listen_addr: "0.0.0.0"  # Listen address (IPv4/IPv6)
  metrics_port: 8080      # HTTP metrics server port
  metrics_path: "/metrics" # Prometheus metrics endpoint path

# Performance tuning
performance:
  buffer_size: 65536      # UDP receive buffer size
  worker_count: 8         # Number of record processing workers
  batch_size: 100         # Batch processing size
  queue_size: 10000       # Channel queue size

# Data aggregation settings
aggregation:
  # Time windows for aggregation (multiple windows supported)
  time_windows:
    - "1m"                # 1 minute window
    - "5m"                # 5 minute window
    - "15m"               # 15 minute window
    - "1h"                # 1 hour window
  
  # Dimensions for aggregation grouping
  dimensions:
    - "src_addr"          # Source IP address
    - "dst_addr"          # Destination IP address
    - "protocol"          # IP protocol
    - "src_port"          # Source port
    - "dst_port"          # Destination port
    - "in_if"             # Input interface
    - "out_if"            # Output interface
    - "src_country"       # Source country (requires GeoIP)
    - "dst_country"       # Destination country (requires GeoIP)
    - "src_asn"           # Source ASN (requires ASN database)
    - "dst_asn"           # Destination ASN (requires ASN database)

# IP enrichment configuration
enrichment:
  # GeoIP configuration
  geoip_enabled: true
  geoip_path: "/opt/geoip/GeoLite2-Country.mmdb"  # Path to MaxMind GeoIP2 database
  
  # ASN configuration  
  asn_enabled: true
  asn_path: "/opt/geoip/GeoLite2-ASN.mmdb"        # Path to MaxMind ASN database
  
  # Cache settings
  cache_size: 100000      # Maximum cache entries for enrichment data

# Prometheus metrics configuration
metrics:
  namespace: "flow"       # Prometheus namespace
  subsystem: ""           # Prometheus subsystem (optional)
  
  # Labels to include in metrics (affects cardinality)
  enabled_labels:
    - "ports"             # Include src_port, dst_port labels
    - "interfaces"        # Include in_if, out_if labels
    - "geo"               # Include src_country, dst_country labels
    - "asn"               # Include src_asn, dst_asn labels
  
  # Custom static labels added to all metrics
  custom_labels:
    environment: "production"
    datacenter: "dc1"
    collector_id: "flow-01"

# Logging configuration
logging:
  level: "info"           # debug, info, warn, error
  format: "json"          # json, text
```

## GeoIP Database Setup

Download and extract MaxMind databases:

```bash
# Create directory
sudo mkdir -p /opt/geoip

# Download GeoLite2 databases (requires free MaxMind account)
wget -O GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"
wget -O GeoLite2-ASN.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"

# Extract databases
tar -xzf GeoLite2-Country.tar.gz --wildcards --no-anchored '*.mmdb' --strip-components=1
tar -xzf GeoLite2-ASN.tar.gz --wildcards --no-anchored '*.mmdb' --strip-components=1

# Move to target directory
sudo mv *.mmdb /opt/geoip/
```

## Minimal Configuration (No Enrichment)

```yaml
server:
  netflow_port: 2055
  sflow_port: 6343
  ipfix_port: 4739
  listen_addr: "0.0.0.0"
  metrics_port: 8080

performance:
  worker_count: 4
  queue_size: 1000

aggregation:
  time_windows:
    - "1m"
    - "5m"
  dimensions:
    - "src_addr"
    - "dst_addr"
    - "protocol"

enrichment:
  geoip_enabled: false
  asn_enabled: false

metrics:
  namespace: "flow"
  enabled_labels: []

logging:
  level: "info"
```

---

# Prometheus & Grafana Query Examples

## Basic Traffic Metrics

### Total Flows per Second
```promql
# Rate of flows per second
rate(flow_flows_total[1m])

# Top 10 source IPs by flow rate
topk(10, sum(rate(flow_flows_total[5m])) by (src_addr))

# Top 10 destination IPs by flow rate  
topk(10, sum(rate(flow_flows_total[5m])) by (dst_addr))
```

### Bandwidth Metrics
```promql
# Total bandwidth in bits per second
sum(flow_bandwidth_bps)

# Bandwidth by source IP
sum(flow_bandwidth_bps) by (src_addr)

# Bandwidth by destination IP
sum(flow_bandwidth_bps) by (dst_addr)

# Top bandwidth consumers
topk(10, sum(flow_bandwidth_bps) by (src_addr, dst_addr))
```

### Packet Analysis
```promql
# Packet rate per second
rate(flow_packets_total[1m])

# Average packet size in bytes
rate(flow_bytes_total[5m]) / rate(flow_packets_total[5m])

# Packets per flow ratio
rate(flow_packets_total[5m]) / rate(flow_flows_total[5m])
```

## Protocol Analysis

### Traffic by Protocol
```promql
# Bandwidth by protocol
sum(flow_bandwidth_bps) by (protocol)

# Flow rate by protocol
sum(rate(flow_flows_total[5m])) by (protocol)

# Protocol distribution (percentage)
sum(rate(flow_bytes_total[5m])) by (protocol) / sum(rate(flow_bytes_total[5m])) * 100
```

### Port Analysis
```promql
# Top destination ports by bandwidth
topk(20, sum(flow_bandwidth_bps) by (dst_port))

# Top source ports by flow count
topk(20, sum(rate(flow_flows_total[5m])) by (src_port))

# Web traffic (ports 80, 443)
sum(flow_bandwidth_bps{dst_port=~"80|443"})

# SSH traffic analysis
sum(rate(flow_flows_total[5m]){dst_port="22"}) by (src_addr)
```

## Geographic Analysis (GeoIP Enabled)

### Traffic by Country
```promql
# Bandwidth by source country
sum(flow_bandwidth_bps) by (src_country)

# Bandwidth by destination country
sum(flow_bandwidth_bps) by (dst_country)

# International vs domestic traffic
sum(flow_bandwidth_bps{src_country!="",dst_country!="",src_country!=dst_country})
sum(flow_bandwidth_bps{src_country!="",dst_country!="",src_country==dst_country})

# Top countries by incoming traffic
topk(10, sum(flow_bandwidth_bps) by (src_country))
```

### Cross-Border Traffic Matrix
```promql
# Traffic matrix between countries
sum(flow_bandwidth_bps) by (src_country, dst_country)

# Outbound traffic from specific country
sum(flow_bandwidth_bps{src_country="US"}) by (dst_country)
```

## ASN Analysis

### Traffic by Autonomous System
```promql
# Bandwidth by source ASN
sum(flow_bandwidth_bps) by (src_asn)

# Top ASNs by traffic volume
topk(15, sum(rate(flow_bytes_total[5m])) by (src_asn))

# Peering analysis - traffic between ASNs
sum(flow_bandwidth_bps{src_asn!="",dst_asn!="",src_asn!=dst_asn}) by (src_asn, dst_asn)

# Major cloud provider traffic
sum(flow_bandwidth_bps{src_asn=~"15169|16509|8075"}) by (src_asn)
# 15169: Google, 16509: Amazon, 8075: Microsoft
```

## Interface Analysis

### Per-Interface Metrics
```promql
# Inbound traffic per interface
sum(flow_bandwidth_bps) by (in_if)

# Outbound traffic per interface  
sum(flow_bandwidth_bps) by (out_if)

# Interface utilization (assuming 1Gbps interfaces)
sum(flow_bandwidth_bps) by (in_if) / 1000000000 * 100

# Top interfaces by flow count
topk(10, sum(rate(flow_flows_total[5m])) by (in_if))
```

## Security & Anomaly Detection

### Potential DDoS Detection
```promql
# High packet rate to single destination
topk(5, sum(rate(flow_packets_total[1m])) by (dst_addr))

# Many flows from single source
topk(10, sum(rate(flow_flows_total[1m])) by (src_addr))

# Small packet size anomaly (potential attack)
bottomk(10, rate(flow_bytes_total[5m]) / rate(flow_packets_total[5m])) by (src_addr, dst_addr)

# Unusual port activity
sum(rate(flow_flows_total[5m]){dst_port!~"80|443|53|22|25|110|993|995"}) by (dst_port)
```

### Port Scanning Detection
```promql
# High number of unique destination ports from single source
count(sum(rate(flow_flows_total[5m])) by (src_addr, dst_port)) by (src_addr)

# Failed connection attempts (assuming low byte count indicates failed connections)
sum(rate(flow_flows_total[5m]){bytes<100}) by (src_addr)
```

## System Health Monitoring

### Collector Performance
```promql
# Collection rate
rate(flow_received_packets_total[1m])
rate(flow_parsed_records_total[1m])  
rate(flow_dropped_records_total[1m])

# Drop rate percentage
rate(flow_dropped_records_total[1m]) / rate(flow_received_packets_total[1m]) * 100

# Processing latency
histogram_quantile(0.95, rate(flow_processing_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(flow_processing_duration_seconds_bucket[5m]))

# Queue depth
flow_worker_queue_length
```

## Grafana Dashboard Panels

### Single Stat Panels
- Total Bandwidth: `sum(flow_bandwidth_bps)`
- Total Flows/sec: `sum(rate(flow_flows_total[1m]))`  
- Drop Rate: `rate(flow_dropped_records_total[1m]) / rate(flow_received_packets_total[1m]) * 100`

### Time Series Graphs
- Bandwidth Over Time: `sum(flow_bandwidth_bps)`
- Flow Rate: `sum(rate(flow_flows_total[1m]))`
- Protocol Distribution: `sum(flow_bandwidth_bps) by (protocol)`

### Top Lists (Table Panels)
- Top Sources: `topk(10, sum(rate(flow_bytes_total[5m])) by (src_addr))`
- Top Destinations: `topk(10, sum(rate(flow_bytes_total[5m])) by (dst_addr))`
- Top Ports: `topk(20, sum(flow_bandwidth_bps) by (dst_port))`

### Heatmaps
- Traffic Matrix: `sum(flow_bandwidth_bps) by (src_country, dst_country)`
- Port Activity: `sum(rate(flow_flows_total[5m])) by (dst_port)`

## Alerting Rules

### High Traffic Alert
```yaml
- alert: HighBandwidthUsage
  expr: sum(flow_bandwidth_bps) > 800000000  # 800 Mbps
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "High bandwidth usage detected"
    description: "Total bandwidth usage is {{ $value | humanize }}bps"
```

### DDoS Detection Alert
```yaml
- alert: PotentialDDoSAttack
  expr: sum(rate(flow_packets_total[1m])) by (dst_addr) > 10000
  for: 30s
  labels:
    severity: critical
  annotations:
    summary: "Potential DDoS attack detected"
    description: "High packet rate to {{ $labels.dst_addr }}: {{ $value | humanize }} pps"
```

### Collector Health Alert
```yaml
- alert: FlowCollectorDrops
  expr: rate(flow_dropped_records_total[5m]) / rate(flow_received_packets_total[5m]) > 0.1
  for: 1m
  labels:
    severity: warning
  annotations:
    summary: "Flow collector dropping packets"
    description: "Drop rate is {{ $value | humanizePercentage }}"
```
