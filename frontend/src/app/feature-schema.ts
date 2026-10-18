export type Feature = {
  name: string;
  label: string;
  kind: 'number' | 'category';
  required: boolean;
  options?: string[];
  min?: number;
  max?: number;
};

export const FEATURES: Feature[] = [
  {
    "name": "arp.opcode",
    "label": "arp.opcode",
    "kind": "number",
    "required": true
  },
  {
    "name": "arp.hw.size",
    "label": "arp.hw.size",
    "kind": "number",
    "required": true
  },
  {
    "name": "icmp.checksum",
    "label": "icmp.checksum",
    "kind": "number",
    "required": true
  },
  {
    "name": "icmp.seq_le",
    "label": "icmp.seq_le",
    "kind": "number",
    "required": true
  },
  {
    "name": "http.content_length",
    "label": "http.content_length",
    "kind": "number",
    "required": true
  },
  {
    "name": "http.request.method",
    "label": "http.request.method",
    "kind": "category",
    "required": true,
    "options": [
      "0",
      "GET",
      "OPTIONS",
      "POST",
      "TRACE"
    ]
  },
  {
    "name": "http.referer",
    "label": "http.referer",
    "kind": "category",
    "required": true,
    "options": [
      "() { _; } >_[$($())] { echo 93e4r0-CVE-2014-6278: true; echo;echo; }",
      "0",
      "127.0.0.1"
    ]
  },
  {
    "name": "http.request.version",
    "label": "http.request.version",
    "kind": "category",
    "required": true,
    "options": [
      "-a HTTP/1.1",
      "/etc/passwd|?data=Download HTTP/1.1",
      "0",
      "By Dr HTTP/1.1",
      "HTTP/1.0",
      "HTTP/1.1",
      "Src=javascript:alert('Vulnerable')><Img Src=\\\" HTTP/1.1"
    ]
  },
  {
    "name": "http.response",
    "label": "http.response",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.ack",
    "label": "tcp.ack",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.ack_raw",
    "label": "tcp.ack_raw",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.checksum",
    "label": "tcp.checksum",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.connection.fin",
    "label": "tcp.connection.fin",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.connection.rst",
    "label": "tcp.connection.rst",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.connection.syn",
    "label": "tcp.connection.syn",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.connection.synack",
    "label": "tcp.connection.synack",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.flags",
    "label": "tcp.flags",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.flags.ack",
    "label": "tcp.flags.ack",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.len",
    "label": "tcp.len",
    "kind": "number",
    "required": true
  },
  {
    "name": "tcp.seq",
    "label": "tcp.seq",
    "kind": "number",
    "required": true
  },
  {
    "name": "udp.stream",
    "label": "udp.stream",
    "kind": "number",
    "required": true
  },
  {
    "name": "udp.time_delta",
    "label": "udp.time_delta",
    "kind": "number",
    "required": true
  },
  {
    "name": "dns.qry.name",
    "label": "dns.qry.name",
    "kind": "number",
    "required": true
  },
  {
    "name": "dns.qry.name.len",
    "label": "dns.qry.name.len",
    "kind": "number",
    "required": true
  },
  {
    "name": "dns.qry.qu",
    "label": "dns.qry.qu",
    "kind": "number",
    "required": true
  },
  {
    "name": "dns.retransmission",
    "label": "dns.retransmission",
    "kind": "number",
    "required": true
  },
  {
    "name": "dns.retransmit_request",
    "label": "dns.retransmit_request",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.conack.flags",
    "label": "mqtt.conack.flags",
    "kind": "category",
    "required": true,
    "options": [
      "0",
      "0x00000000"
    ]
  },
  {
    "name": "mqtt.conflag.cleansess",
    "label": "mqtt.conflag.cleansess",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.conflags",
    "label": "mqtt.conflags",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.hdrflags",
    "label": "mqtt.hdrflags",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.len",
    "label": "mqtt.len",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.msgtype",
    "label": "mqtt.msgtype",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.proto_len",
    "label": "mqtt.proto_len",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.protoname",
    "label": "mqtt.protoname",
    "kind": "category",
    "required": true,
    "options": [
      "0",
      "MQTT"
    ]
  },
  {
    "name": "mqtt.topic",
    "label": "mqtt.topic",
    "kind": "category",
    "required": true,
    "options": [
      "0",
      "Temperature_and_Humidity"
    ]
  },
  {
    "name": "mqtt.topic_len",
    "label": "mqtt.topic_len",
    "kind": "number",
    "required": true
  },
  {
    "name": "mqtt.ver",
    "label": "mqtt.ver",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_service_port",
    "label": "psfe_service_port",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_ephemeral_port",
    "label": "psfe_ephemeral_port",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_port_span",
    "label": "psfe_port_span",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_pkt_direction",
    "label": "psfe_pkt_direction",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_is_http_service",
    "label": "psfe_is_http_service",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_is_mqtt_service",
    "label": "psfe_is_mqtt_service",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_is_iot_c2_service",
    "label": "psfe_is_iot_c2_service",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_is_boundary_probe",
    "label": "psfe_is_boundary_probe",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_udp_active",
    "label": "psfe_udp_active",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_tcp_opt_bytelen",
    "label": "psfe_tcp_opt_bytelen",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_tcp_opt_has_mss",
    "label": "psfe_tcp_opt_has_mss",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_tcp_opt_has_ts",
    "label": "psfe_tcp_opt_has_ts",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_tcp_pay_bytelen",
    "label": "psfe_tcp_pay_bytelen",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_tcp_pay_first_byte",
    "label": "psfe_tcp_pay_first_byte",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_tcp_pay_entropy",
    "label": "psfe_tcp_pay_entropy",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_http_uri_path_len",
    "label": "psfe_http_uri_path_len",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_http_query_len",
    "label": "psfe_http_query_len",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_http_file_data_len",
    "label": "psfe_http_file_data_len",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_mqtt_msg_bytelen",
    "label": "psfe_mqtt_msg_bytelen",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_app_sqli_flag",
    "label": "psfe_app_sqli_flag",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_app_xss_flag",
    "label": "psfe_app_xss_flag",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_app_upload_flag",
    "label": "psfe_app_upload_flag",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_app_auth_flag",
    "label": "psfe_app_auth_flag",
    "kind": "number",
    "required": true
  },
  {
    "name": "psfe_app_timeout_flag",
    "label": "psfe_app_timeout_flag",
    "kind": "number",
    "required": true
  }
];

export const SAMPLE_PRESETS: Record<string, Record<string, string | number>> = {
  "Normal": {
    "arp.opcode": 0.0,
    "arp.hw.size": 0.0,
    "icmp.checksum": 0.0,
    "icmp.seq_le": 0.0,
    "http.content_length": 0.0,
    "http.request.method": "0",
    "http.referer": "0",
    "http.request.version": "0",
    "http.response": 0.0,
    "tcp.ack": 5.0,
    "tcp.ack_raw": 95353586.0,
    "tcp.checksum": 26067.0,
    "tcp.connection.fin": 1.0,
    "tcp.connection.rst": 0.0,
    "tcp.connection.syn": 0.0,
    "tcp.connection.synack": 0.0,
    "tcp.flags": 25.0,
    "tcp.flags.ack": 1.0,
    "tcp.len": 2.0,
    "tcp.seq": 56.0,
    "udp.stream": 0.0,
    "udp.time_delta": 0.0,
    "dns.qry.name": 0.0,
    "dns.qry.name.len": 0.0,
    "dns.qry.qu": 0.0,
    "dns.retransmission": 0.0,
    "dns.retransmit_request": 0.0,
    "mqtt.conack.flags": "0",
    "mqtt.conflag.cleansess": 0.0,
    "mqtt.conflags": 0.0,
    "mqtt.hdrflags": 224.0,
    "mqtt.len": 0.0,
    "mqtt.msgtype": 14.0,
    "mqtt.proto_len": 0.0,
    "mqtt.protoname": "0",
    "mqtt.topic": "0",
    "mqtt.topic_len": 0.0,
    "mqtt.ver": 0.0,
    "psfe_service_port": 1883.0,
    "psfe_ephemeral_port": 54819.0,
    "psfe_port_span": 52936.0,
    "psfe_pkt_direction": 1.0,
    "psfe_is_http_service": 0.0,
    "psfe_is_mqtt_service": 1.0,
    "psfe_is_iot_c2_service": 0.0,
    "psfe_is_boundary_probe": 0.0,
    "psfe_udp_active": 0.0,
    "psfe_tcp_opt_bytelen": 0.0,
    "psfe_tcp_opt_has_mss": 0.0,
    "psfe_tcp_opt_has_ts": 0.0,
    "psfe_tcp_pay_bytelen": 2.0,
    "psfe_tcp_pay_first_byte": 224.0,
    "psfe_tcp_pay_entropy": 0.8112781047821045,
    "psfe_http_uri_path_len": 0.0,
    "psfe_http_query_len": 0.0,
    "psfe_http_file_data_len": 0.0,
    "psfe_mqtt_msg_bytelen": 0.0,
    "psfe_app_sqli_flag": 0.0,
    "psfe_app_xss_flag": 0.0,
    "psfe_app_upload_flag": 0.0,
    "psfe_app_auth_flag": 0.0,
    "psfe_app_timeout_flag": 0.0
  },
  "DDoS_TCP": {
    "arp.opcode": 0.0,
    "arp.hw.size": 0.0,
    "icmp.checksum": 0.0,
    "icmp.seq_le": 0.0,
    "http.content_length": 0.0,
    "http.request.method": "0",
    "http.referer": "0",
    "http.request.version": "0",
    "http.response": 0.0,
    "tcp.ack": 121.0,
    "tcp.ack_raw": 976986157.0,
    "tcp.checksum": 56248.0,
    "tcp.connection.fin": 0.0,
    "tcp.connection.rst": 1.0,
    "tcp.connection.syn": 0.0,
    "tcp.connection.synack": 0.0,
    "tcp.flags": 20.0,
    "tcp.flags.ack": 1.0,
    "tcp.len": 0.0,
    "tcp.seq": 1.0,
    "udp.stream": 0.0,
    "udp.time_delta": 0.0,
    "dns.qry.name": 0.0,
    "dns.qry.name.len": 0.0,
    "dns.qry.qu": 0.0,
    "dns.retransmission": 0.0,
    "dns.retransmit_request": 0.0,
    "mqtt.conack.flags": "0",
    "mqtt.conflag.cleansess": 0.0,
    "mqtt.conflags": 0.0,
    "mqtt.hdrflags": 0.0,
    "mqtt.len": 0.0,
    "mqtt.msgtype": 0.0,
    "mqtt.proto_len": 0.0,
    "mqtt.protoname": "0",
    "mqtt.topic": "0",
    "mqtt.topic_len": 0.0,
    "mqtt.ver": 0.0,
    "psfe_service_port": 80.0,
    "psfe_ephemeral_port": 39267.0,
    "psfe_port_span": 39187.0,
    "psfe_pkt_direction": -1.0,
    "psfe_is_http_service": 1.0,
    "psfe_is_mqtt_service": 0.0,
    "psfe_is_iot_c2_service": 0.0,
    "psfe_is_boundary_probe": 0.0,
    "psfe_udp_active": 0.0,
    "psfe_tcp_opt_bytelen": 0.0,
    "psfe_tcp_opt_has_mss": 0.0,
    "psfe_tcp_opt_has_ts": 0.0,
    "psfe_tcp_pay_bytelen": 0.0,
    "psfe_tcp_pay_first_byte": 0.0,
    "psfe_tcp_pay_entropy": 0.0,
    "psfe_http_uri_path_len": 0.0,
    "psfe_http_query_len": 0.0,
    "psfe_http_file_data_len": 0.0,
    "psfe_mqtt_msg_bytelen": 0.0,
    "psfe_app_sqli_flag": 0.0,
    "psfe_app_xss_flag": 0.0,
    "psfe_app_upload_flag": 0.0,
    "psfe_app_auth_flag": 0.0,
    "psfe_app_timeout_flag": 0.0
  },
  "SQL_injection": {
    "arp.opcode": 0.0,
    "arp.hw.size": 0.0,
    "icmp.checksum": 0.0,
    "icmp.seq_le": 0.0,
    "http.content_length": 0.0,
    "http.request.method": "GET",
    "http.referer": "0",
    "http.request.version": "HTTP/1.1",
    "http.response": 0.0,
    "tcp.ack": 1.0,
    "tcp.ack_raw": 4033201737.0,
    "tcp.checksum": 7669.0,
    "tcp.connection.fin": 0.0,
    "tcp.connection.rst": 0.0,
    "tcp.connection.syn": 0.0,
    "tcp.connection.synack": 0.0,
    "tcp.flags": 24.0,
    "tcp.flags.ack": 1.0,
    "tcp.len": 306.0,
    "tcp.seq": 1.0,
    "udp.stream": 0.0,
    "udp.time_delta": 0.0,
    "dns.qry.name": 0.0,
    "dns.qry.name.len": 0.0,
    "dns.qry.qu": 0.0,
    "dns.retransmission": 0.0,
    "dns.retransmit_request": 0.0,
    "mqtt.conack.flags": "0",
    "mqtt.conflag.cleansess": 0.0,
    "mqtt.conflags": 0.0,
    "mqtt.hdrflags": 0.0,
    "mqtt.len": 0.0,
    "mqtt.msgtype": 0.0,
    "mqtt.proto_len": 0.0,
    "mqtt.protoname": "0",
    "mqtt.topic": "0",
    "mqtt.topic_len": 0.0,
    "mqtt.ver": 0.0,
    "psfe_service_port": 80.0,
    "psfe_ephemeral_port": 39674.0,
    "psfe_port_span": 39594.0,
    "psfe_pkt_direction": 1.0,
    "psfe_is_http_service": 1.0,
    "psfe_is_mqtt_service": 0.0,
    "psfe_is_iot_c2_service": 0.0,
    "psfe_is_boundary_probe": 0.0,
    "psfe_udp_active": 0.0,
    "psfe_tcp_opt_bytelen": 12.0,
    "psfe_tcp_opt_has_mss": 0.0,
    "psfe_tcp_opt_has_ts": 1.0,
    "psfe_tcp_pay_bytelen": 306.0,
    "psfe_tcp_pay_first_byte": 71.0,
    "psfe_tcp_pay_entropy": 3.219602584838867,
    "psfe_http_uri_path_len": 57.0,
    "psfe_http_query_len": 23.0,
    "psfe_http_file_data_len": 0.0,
    "psfe_mqtt_msg_bytelen": 0.0,
    "psfe_app_sqli_flag": 1.0,
    "psfe_app_xss_flag": 0.0,
    "psfe_app_upload_flag": 0.0,
    "psfe_app_auth_flag": 0.0,
    "psfe_app_timeout_flag": 0.0
  },
  "Ransomware": {
    "arp.opcode": 0.0,
    "arp.hw.size": 0.0,
    "icmp.checksum": 0.0,
    "icmp.seq_le": 0.0,
    "http.content_length": 0.0,
    "http.request.method": "0",
    "http.referer": "0",
    "http.request.version": "0",
    "http.response": 0.0,
    "tcp.ack": 1.0,
    "tcp.ack_raw": 2013966124.0,
    "tcp.checksum": 58792.0,
    "tcp.connection.fin": 0.0,
    "tcp.connection.rst": 0.0,
    "tcp.connection.syn": 0.0,
    "tcp.connection.synack": 0.0,
    "tcp.flags": 24.0,
    "tcp.flags.ack": 1.0,
    "tcp.len": 464.0,
    "tcp.seq": 1181233.0,
    "udp.stream": 0.0,
    "udp.time_delta": 0.0,
    "dns.qry.name": 0.0,
    "dns.qry.name.len": 0.0,
    "dns.qry.qu": 0.0,
    "dns.retransmission": 0.0,
    "dns.retransmit_request": 0.0,
    "mqtt.conack.flags": "0",
    "mqtt.conflag.cleansess": 0.0,
    "mqtt.conflags": 0.0,
    "mqtt.hdrflags": 0.0,
    "mqtt.len": 0.0,
    "mqtt.msgtype": 0.0,
    "mqtt.proto_len": 0.0,
    "mqtt.protoname": "0",
    "mqtt.topic": "0",
    "mqtt.topic_len": 0.0,
    "mqtt.ver": 0.0,
    "psfe_service_port": 4321.0,
    "psfe_ephemeral_port": 47924.0,
    "psfe_port_span": 43603.0,
    "psfe_pkt_direction": 1.0,
    "psfe_is_http_service": 0.0,
    "psfe_is_mqtt_service": 0.0,
    "psfe_is_iot_c2_service": 1.0,
    "psfe_is_boundary_probe": 0.0,
    "psfe_udp_active": 0.0,
    "psfe_tcp_opt_bytelen": 12.0,
    "psfe_tcp_opt_has_mss": 0.0,
    "psfe_tcp_opt_has_ts": 1.0,
    "psfe_tcp_pay_bytelen": 464.0,
    "psfe_tcp_pay_first_byte": 139.0,
    "psfe_tcp_pay_entropy": 3.652017831802368,
    "psfe_http_uri_path_len": 0.0,
    "psfe_http_query_len": 0.0,
    "psfe_http_file_data_len": 0.0,
    "psfe_mqtt_msg_bytelen": 0.0,
    "psfe_app_sqli_flag": 0.0,
    "psfe_app_xss_flag": 0.0,
    "psfe_app_upload_flag": 0.0,
    "psfe_app_auth_flag": 0.0,
    "psfe_app_timeout_flag": 0.0
  }
};
