export type FeatureGroup = 'psfe' | 'tcp' | 'http' | 'mqtt' | 'link_net';

export interface FeatureMeta {
  group: FeatureGroup;
  displayLabel: string;
  unit?: string;
  isBinary?: boolean;
  hint: string;
}

export const FEATURE_GROUPS: { id: 'all' | FeatureGroup; label: string }[] = [
  { id: 'all', label: 'All Layers' },
  { id: 'psfe', label: 'PP-PSFE Engineered' },
  { id: 'tcp', label: 'TCP Transport' },
  { id: 'http', label: 'HTTP Layer' },
  { id: 'mqtt', label: 'MQTT Broker' },
  { id: 'link_net', label: 'UDP / DNS / ICMP / ARP' },
];

export const FEATURE_METADATA: Record<string, FeatureMeta> = {
  'arp.opcode': {
    group: 'link_net',
    displayLabel: 'ARP Opcode',
    unit: 'code',
    hint: 'ARP operation code (1 = request, 2 = reply, 0 = inactive).'
  },
  'arp.hw.size': {
    group: 'link_net',
    displayLabel: 'ARP Hardware Size',
    unit: 'bytes',
    hint: 'Hardware address length in ARP header (6 bytes for Ethernet).'
  },
  'icmp.checksum': {
    group: 'link_net',
    displayLabel: 'ICMP Checksum',
    unit: 'hex16',
    hint: '16-bit ICMP header checksum value.'
  },
  'icmp.seq_le': {
    group: 'link_net',
    displayLabel: 'ICMP Sequence (LE)',
    unit: 'seq',
    hint: 'Little-endian ICMP echo sequence counter.'
  },
  'http.content_length': {
    group: 'http',
    displayLabel: 'HTTP Content-Length',
    unit: 'bytes',
    hint: 'Declared HTTP entity body length in bytes.'
  },
  'http.request.method': {
    group: 'http',
    displayLabel: 'HTTP Method',
    hint: 'HTTP request verb (GET, POST, OPTIONS, TRACE, or 0 if non-HTTP).'
  },
  'http.referer': {
    group: 'http',
    displayLabel: 'HTTP Referer',
    hint: 'Sanitized HTTP Referer header category.'
  },
  'http.request.version': {
    group: 'http',
    displayLabel: 'HTTP Version / Raw Header',
    hint: 'HTTP protocol version token or malformed probe header.'
  },
  'http.response': {
    group: 'http',
    displayLabel: 'HTTP Response Indicator',
    isBinary: true,
    hint: 'Indicates whether packet carries an HTTP response.'
  },
  'tcp.ack': {
    group: 'tcp',
    displayLabel: 'TCP Relative Ack',
    unit: 'seq',
    hint: 'Relative acknowledgment counter within the TCP stream.'
  },
  'tcp.ack_raw': {
    group: 'tcp',
    displayLabel: 'TCP Raw Ack',
    unit: 'uint32',
    hint: 'Raw 32-bit acknowledgment number from TCP header.'
  },
  'tcp.checksum': {
    group: 'tcp',
    displayLabel: 'TCP Checksum',
    unit: 'hex16',
    hint: '16-bit TCP header checksum.'
  },
  'tcp.connection.fin': {
    group: 'tcp',
    displayLabel: 'TCP FIN Flag',
    isBinary: true,
    hint: 'Connection teardown FIN flag active.'
  },
  'tcp.connection.rst': {
    group: 'tcp',
    displayLabel: 'TCP RST Flag',
    isBinary: true,
    hint: 'Abrupt connection reset RST flag active.'
  },
  'tcp.connection.syn': {
    group: 'tcp',
    displayLabel: 'TCP SYN Flag',
    isBinary: true,
    hint: 'Handshake initiation SYN flag active.'
  },
  'tcp.connection.synack': {
    group: 'tcp',
    displayLabel: 'TCP SYN-ACK Flag',
    isBinary: true,
    hint: 'Handshake acknowledgment SYN-ACK flag active.'
  },
  'tcp.flags': {
    group: 'tcp',
    displayLabel: 'TCP Flags Bitmask',
    unit: 'mask',
    hint: 'Decimal representation of TCP control bits (e.g., 24 = PSH+ACK, 20 = RST+ACK).'
  },
  'tcp.flags.ack': {
    group: 'tcp',
    displayLabel: 'TCP ACK Bit',
    isBinary: true,
    hint: 'Acknowledgment control bit set in TCP header.'
  },
  'tcp.len': {
    group: 'tcp',
    displayLabel: 'TCP Segment Length',
    unit: 'bytes',
    hint: 'TCP payload segment size in bytes.'
  },
  'tcp.seq': {
    group: 'tcp',
    displayLabel: 'TCP Sequence Number',
    unit: 'seq',
    hint: 'Relative TCP sequence offset.'
  },
  'udp.stream': {
    group: 'link_net',
    displayLabel: 'UDP Stream Index',
    unit: 'id',
    hint: 'Captured UDP flow stream identifier.'
  },
  'udp.time_delta': {
    group: 'link_net',
    displayLabel: 'UDP Inter-Packet Delta',
    unit: 'sec',
    hint: 'Time delta since previous packet in UDP stream.'
  },
  'dns.qry.name': {
    group: 'link_net',
    displayLabel: 'DNS Query Name Code',
    unit: 'code',
    hint: 'Encoded DNS query name field.'
  },
  'dns.qry.name.len': {
    group: 'link_net',
    displayLabel: 'DNS Query Length',
    unit: 'chars',
    hint: 'Character length of queried DNS hostname.'
  },
  'dns.qry.qu': {
    group: 'link_net',
    displayLabel: 'DNS Unicast Query Bit',
    unit: 'flag',
    hint: 'mDNS / DNS unicast response request indicator.'
  },
  'dns.retransmission': {
    group: 'link_net',
    displayLabel: 'DNS Retransmission',
    isBinary: true,
    hint: 'Packet is a retransmitted DNS message.'
  },
  'dns.retransmit_request': {
    group: 'link_net',
    displayLabel: 'DNS Retransmit Request',
    isBinary: true,
    hint: 'Repeated DNS query observed.'
  },
  'mqtt.conack.flags': {
    group: 'mqtt',
    displayLabel: 'MQTT CONNACK Flags',
    hint: 'MQTT connection acknowledgment flags category.'
  },
  'mqtt.conflag.cleansess': {
    group: 'mqtt',
    displayLabel: 'MQTT Clean Session',
    isBinary: true,
    hint: 'Clean session flag in MQTT CONNECT header.'
  },
  'mqtt.conflags': {
    group: 'mqtt',
    displayLabel: 'MQTT Connect Flags',
    unit: 'mask',
    hint: 'Decimal bitmask of MQTT CONNECT flags.'
  },
  'mqtt.hdrflags': {
    group: 'mqtt',
    displayLabel: 'MQTT Header Flags',
    unit: 'mask',
    hint: 'Fixed header control byte (e.g., 224 = DISCONNECT, 48 = PUBLISH).'
  },
  'mqtt.len': {
    group: 'mqtt',
    displayLabel: 'MQTT Remaining Length',
    unit: 'bytes',
    hint: 'MQTT variable header + payload byte length.'
  },
  'mqtt.msgtype': {
    group: 'mqtt',
    displayLabel: 'MQTT Message Type',
    unit: 'type',
    hint: 'Control packet type (1 = CONNECT, 3 = PUBLISH, 14 = DISCONNECT).'
  },
  'mqtt.proto_len': {
    group: 'mqtt',
    displayLabel: 'MQTT Protocol Name Length',
    unit: 'bytes',
    hint: 'Length of protocol string in MQTT CONNECT packet.'
  },
  'mqtt.protoname': {
    group: 'mqtt',
    displayLabel: 'MQTT Protocol Name',
    hint: 'Protocol identifier string (MQTT or 0).'
  },
  'mqtt.topic': {
    group: 'mqtt',
    displayLabel: 'MQTT Topic',
    hint: 'Telemetry topic category (e.g., Temperature_and_Humidity or 0).'
  },
  'mqtt.topic_len': {
    group: 'mqtt',
    displayLabel: 'MQTT Topic Length',
    unit: 'chars',
    hint: 'Character count of MQTT publish/subscribe topic.'
  },
  'mqtt.ver': {
    group: 'mqtt',
    displayLabel: 'MQTT Version',
    unit: 'ver',
    hint: 'MQTT protocol revision (4 = v3.1.1).'
  },
  'psfe_service_port': {
    group: 'psfe',
    displayLabel: 'Service Port',
    unit: 'port',
    hint: 'Well-known endpoint port (< 10000), anonymized from raw IP tuples.'
  },
  'psfe_ephemeral_port': {
    group: 'psfe',
    displayLabel: 'Ephemeral Port',
    unit: 'port',
    hint: 'Higher-numbered client/ephemeral socket port.'
  },
  'psfe_port_span': {
    group: 'psfe',
    displayLabel: 'Port Span',
    unit: 'delta',
    hint: 'Absolute difference |src_port - dst_port|.'
  },
  'psfe_pkt_direction': {
    group: 'psfe',
    displayLabel: 'Packet Direction',
    unit: 'sign',
    hint: '+1 = Client to Service (src > dst), -1 = Service to Client, 0 = Equal.'
  },
  'psfe_is_http_service': {
    group: 'psfe',
    displayLabel: 'HTTP Service Port',
    isBinary: true,
    hint: 'Endpoint port matches 80, 443, or 8080.'
  },
  'psfe_is_mqtt_service': {
    group: 'psfe',
    displayLabel: 'MQTT Broker Port',
    isBinary: true,
    hint: 'Endpoint port matches standard MQTT broker port 1883.'
  },
  'psfe_is_iot_c2_service': {
    group: 'psfe',
    displayLabel: 'IoT C2 Port Signature',
    isBinary: true,
    hint: 'Endpoint port matches known C2 ports (4321, 3333, 5900).'
  },
  'psfe_is_boundary_probe': {
    group: 'psfe',
    displayLabel: 'Boundary Probe Port',
    isBinary: true,
    hint: 'Endpoint port equals 65535 (max TCP/UDP boundary scan).'
  },
  'psfe_udp_active': {
    group: 'psfe',
    displayLabel: 'UDP Transport Active',
    isBinary: true,
    hint: 'Active UDP port observed in flow.'
  },
  'psfe_tcp_opt_bytelen': {
    group: 'psfe',
    displayLabel: 'TCP Options Byte Length',
    unit: 'bytes',
    hint: 'Decoded byte length of raw TCP options header.'
  },
  'psfe_tcp_opt_has_mss': {
    group: 'psfe',
    displayLabel: 'TCP Option: MSS',
    isBinary: true,
    hint: 'TCP Maximum Segment Size option (0x0204) present.'
  },
  'psfe_tcp_opt_has_ts': {
    group: 'psfe',
    displayLabel: 'TCP Option: Timestamp',
    isBinary: true,
    hint: 'TCP Timestamp option (0x080a) present.'
  },
  'psfe_tcp_pay_bytelen': {
    group: 'psfe',
    displayLabel: 'TCP Payload Byte Length',
    unit: 'bytes',
    hint: 'Length of raw TCP payload in bytes.'
  },
  'psfe_tcp_pay_first_byte': {
    group: 'psfe',
    displayLabel: 'Payload First Byte',
    unit: '0–255',
    hint: 'Leading byte value of TCP payload (e.g., 71 = ASCII "G" for GET).'
  },
  'psfe_tcp_pay_entropy': {
    group: 'psfe',
    displayLabel: 'Payload Shannon Entropy',
    unit: '0–4 bits',
    hint: 'Hex-nybble Shannon entropy over first 64 chars (0 = empty, up to 4.0 = dense/encrypted).'
  },
  'psfe_http_uri_path_len': {
    group: 'psfe',
    displayLabel: 'HTTP URI Path Length',
    unit: 'chars',
    hint: 'Character length of HTTP request URI path.'
  },
  'psfe_http_query_len': {
    group: 'psfe',
    displayLabel: 'HTTP Query String Length',
    unit: 'chars',
    hint: 'Character length of HTTP query parameters.'
  },
  'psfe_http_file_data_len': {
    group: 'psfe',
    displayLabel: 'HTTP File Body Length',
    unit: 'chars',
    hint: 'Length of HTTP uploaded file payload.'
  },
  'psfe_mqtt_msg_bytelen': {
    group: 'psfe',
    displayLabel: 'MQTT Message Byte Length',
    unit: 'bytes',
    hint: 'Byte length of decoded MQTT message body.'
  },
  'psfe_app_sqli_flag': {
    group: 'psfe',
    displayLabel: 'App SQLi Pattern Flag',
    isBinary: true,
    hint: 'SQL injection token signature detected in URI or body.'
  },
  'psfe_app_xss_flag': {
    group: 'psfe',
    displayLabel: 'App XSS Pattern Flag',
    isBinary: true,
    hint: 'Cross-site scripting payload signature detected.'
  },
  'psfe_app_upload_flag': {
    group: 'psfe',
    displayLabel: 'App Upload Activity Flag',
    isBinary: true,
    hint: 'File upload transfer pattern detected in HTTP request.'
  },
  'psfe_app_auth_flag': {
    group: 'psfe',
    displayLabel: 'App Auth Attempt Flag',
    isBinary: true,
    hint: 'Credential or login form activity detected.'
  },
  'psfe_app_timeout_flag': {
    group: 'psfe',
    displayLabel: 'App Timeout Flag',
    isBinary: true,
    hint: 'Application-layer connection timeout indicator.'
  },
};
