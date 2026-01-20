// src/types/security.ts
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'OTHER';

export interface Packet {
  id: string;
  timestamp: number; // ms since epoch
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  length: number;
  flags?: string[];
  payload?: string; // UTF-8 text or hex string fallback
  payloadBytes?: Uint8Array; // raw bytes when available (for hex viewer / reassembly)
  // TCP-specific fields (optional if not present)
  seq?: number;
  ack?: number;
  window?: number;
  // For forensic traceability (offset in original buffer, if available)
  rawOffset?: number;
}

export type ThreatType =
  | 'port_scan'
  | 'brute_force'
  | 'data_exfil'
  | 'malicious_ip'
  | 'dns_anomaly'
  | 'protocol_anomaly';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface ThreatAlert {
  id: string;
  severity: Severity;
  type: ThreatType;
  timestamp: number;
  sourceIP: string;
  description: string;
  affectedPackets: number;
  evidence: string[];
  related?: { ip?: string; port?: number }[];
}

export interface NetworkStats {
  totalPackets: number;
  uniqueIPs: number;
  protocolDistribution: { protocol: string; count: number }[];
  topTalkers: { ip: string; packets: number; bytes: number }[];
  timeRange: { start: number; end: number };
}