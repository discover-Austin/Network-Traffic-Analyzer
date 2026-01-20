/* ThreatDetector - rule-based detection engine that runs client-side.
   - Designed for deterministic, explainable alerts.
   - Uses sliding time windows and safeguards against false positives.
*/

import { Packet, ThreatAlert, Severity } from '../types/security';

type IPPortKey = `${string}_${number}`;

export class ThreatDetector {
  private knownMaliciousIPs = new Set<string>([
    // Example embedded list (small). In production one could ship updated lists offline.
    '185.220.101.1',
    '45.142.212.61'
  ]);

  private dgaPatterns: RegExp[] = [
    /[a-z0-9]{12,}\.(com|net|org|info)/i,
    /\d{7,}\.(ru|cn|pw)/i
  ];

  // Main entry
  detectThreats(packets: Packet[]): ThreatAlert[] {
    // Defensive early return
    if (!packets || packets.length === 0) return [];

    const alerts: ThreatAlert[] = [];

    const portScanAlerts = this.detectPortScans(packets);
    alerts.push(...portScanAlerts);

    const bruteForceAlerts = this.detectBruteForce(packets);
    alerts.push(...bruteForceAlerts);

    const exfilAlerts = this.detectDataExfiltration(packets);
    alerts.push(...exfilAlerts);

    const maliciousIPAlerts = this.detectMaliciousIPs(packets);
    alerts.push(...maliciousIPAlerts);

    const dnsAlerts = this.detectDNSAnomalies(packets);
    alerts.push(...dnsAlerts);

    const protoAlerts = this.detectProtocolAnomalies(packets);
    alerts.push(...protoAlerts);

    // Sort newest first
    return alerts.sort((a, b) => b.timestamp - a.timestamp);
  }

  // Detect port scans: many SYNs to different ports within short timeframe
  private detectPortScans(packets: Packet[]): ThreatAlert[] {
    const windowMs = 60_000; // 1 minute
    const minUniquePorts = 25;
    const alerts: ThreatAlert[] = [];

    // Group SYN-only TCP packets by srcIP -> set of dstPort with timestamp
    const synsBySrc = new Map<string, { ports: Set<number>; firstSeen: number; lastSeen: number }>();

    for (const p of packets) {
      if (p.protocol !== 'TCP') continue;
      if (!p.flags) continue;
      if (p.flags.includes('SYN') && !p.flags.includes('ACK')) {
        const s = synsBySrc.get(p.srcIP) ?? { ports: new Set<number>(), firstSeen: p.timestamp, lastSeen: p.timestamp };
        s.ports.add(p.dstPort);
        s.firstSeen = Math.min(s.firstSeen, p.timestamp);
        s.lastSeen = Math.max(s.lastSeen, p.timestamp);
        synsBySrc.set(p.srcIP, s);
      }
    }

    for (const [ip, meta] of synsBySrc.entries()) {
      if (meta.ports.size >= minUniquePorts && (meta.lastSeen - meta.firstSeen) <= windowMs) {
        alerts.push({
          id: `portscan_${ip}_${Date.now()}`,
          severity: 'high',
          type: 'port_scan',
          timestamp: Date.now(),
          sourceIP: ip,
          description: `Port scan: ${meta.ports.size} unique ports probed within ${(meta.lastSeen - meta.firstSeen) / 1000}s`,
          affectedPackets: meta.ports.size,
          evidence: [
            `Unique destination ports: ${Array.from(meta.ports).slice(0, 10).join(', ')}${meta.ports.size > 10 ? ', ...' : ''}`,
            `Window: ${(meta.lastSeen - meta.firstSeen) / 1000}s`
          ],
          related: []
        });
      }
    }

    return alerts;
  }

  // Brute force: many connection attempts to auth ports
  private detectBruteForce(packets: Packet[]): ThreatAlert[] {
    const authPorts = new Set([22, 23, 3389, 21, 445]);
    const windowMs = 5 * 60_000; // 5 minutes
    const minAttempts = 40;
    const attempts = new Map<IPPortKey, { count: number; first: number; last: number }>();
    const alerts: ThreatAlert[] = [];

    for (const p of packets) {
      if (authPorts.has(p.dstPort)) {
        const key = `${p.srcIP}_${p.dstPort}` as IPPortKey;
        const it = attempts.get(key) ?? { count: 0, first: p.timestamp, last: p.timestamp };
        it.count++;
        it.first = Math.min(it.first, p.timestamp);
        it.last = Math.max(it.last, p.timestamp);
        attempts.set(key, it);
      }
    }

    for (const [key, meta] of attempts.entries()) {
      if (meta.count >= minAttempts && (meta.last - meta.first) <= windowMs) {
        const [ip, portStr] = key.split('_');
        const port = Number(portStr);
        alerts.push({
          id: `bruteforce_${key}_${Date.now()}`,
          severity: 'critical',
          type: 'brute_force',
          timestamp: Date.now(),
          sourceIP: ip,
          description: `Brute force-like activity: ${meta.count} connection attempts to port ${port} within ${(meta.last - meta.first) / 1000}s`,
          affectedPackets: meta.count,
          evidence: [
            `Attempts: ${meta.count}`,
            `Port: ${port}`
          ],
          related: [{ ip, port }]
        });
      }
    }

    return alerts;
  }

  // Data exfil: large outbound transfers from internal -> external hosts
  private detectDataExfiltration(packets: Packet[]): ThreatAlert[] {
    const alerts: ThreatAlert[] = [];
    const bytesByFlow = new Map<string, { bytes: number; first: number; last: number }>();

    for (const p of packets) {
      // Track flows srcIP->dstIP, consider only non-private destination (external)
      if (!this.isPrivateIP(p.dstIP) && this.isPrivateIP(p.srcIP)) {
        const key = `${p.srcIP}_${p.dstIP}`;
        const cur = bytesByFlow.get(key) ?? { bytes: 0, first: p.timestamp, last: p.timestamp };
        cur.bytes += p.length;
        cur.first = Math.min(cur.first, p.timestamp);
        cur.last = Math.max(cur.last, p.timestamp);
        bytesByFlow.set(key, cur);
      }
    }

    for (const [key, meta] of bytesByFlow.entries()) {
      // threshold: 10 MB over any time range
      if (meta.bytes >= 10 * 1024 * 1024) {
        const [srcIP, dstIP] = key.split('_');
        alerts.push({
          id: `exfil_${srcIP}_${dstIP}_${Date.now()}`,
          severity: 'high',
          type: 'data_exfil',
          timestamp: Date.now(),
          sourceIP: srcIP,
          description: `Large outbound transfer (${(meta.bytes / (1024 * 1024)).toFixed(2)} MB) to ${dstIP}`,
          affectedPackets: 0,
          evidence: [
            `Bytes: ${(meta.bytes / (1024 * 1024)).toFixed(2)} MB`,
            `Time window: ${(meta.last - meta.first) / 1000}s`
          ],
          related: [{ ip: dstIP }]
        });
      }
    }

    return alerts;
  }

  private detectMaliciousIPs(packets: Packet[]): ThreatAlert[] {
    const alerts: ThreatAlert[] = [];
    const seen = new Set<string>();

    for (const p of packets) {
      if (this.knownMaliciousIPs.has(p.srcIP) && !seen.has(p.srcIP)) {
        seen.add(p.srcIP);
        const rel = packets.filter(x => x.srcIP === p.srcIP || x.dstIP === p.srcIP);
        alerts.push({
          id: `malip_src_${p.srcIP}_${Date.now()}`,
          severity: 'critical',
          type: 'malicious_ip',
          timestamp: Date.now(),
          sourceIP: p.srcIP,
          description: `Traffic observed from known-malicious IP ${p.srcIP}`,
          affectedPackets: rel.length,
          evidence: [`Known malicious IP (embedded list)`, `Packets: ${rel.length}`],
          related: [{ ip: p.srcIP }]
        });
      }
      if (this.knownMaliciousIPs.has(p.dstIP) && !seen.has(p.dstIP)) {
        seen.add(p.dstIP);
        const rel = packets.filter(x => x.srcIP === p.dstIP || x.dstIP === p.dstIP);
        alerts.push({
          id: `malip_dst_${p.dstIP}_${Date.now()}`,
          severity: 'critical',
          type: 'malicious_ip',
          timestamp: Date.now(),
          sourceIP: p.dstIP,
          description: `Traffic observed to known-malicious IP ${p.dstIP}`,
          affectedPackets: rel.length,
          evidence: [`Known malicious IP (embedded list)`, `Packets: ${rel.length}`],
          related: [{ ip: p.dstIP }]
        });
      }
    }

    return alerts;
  }

  // DNS anomalies: DGA-like names or many unique domains from a single host
  private detectDNSAnomalies(packets: Packet[]): ThreatAlert[] {
    const alerts: ThreatAlert[] = [];
    // Heuristics: collect DNS queries (we assume packet.payload contains DNS query or textual name)
    const domainsBySrc = new Map<string, Set<string>>();

    for (const p of packets) {
      if (p.protocol === 'DNS' && p.payload) {
        // crude extraction: look for ASCII domain-like tokens in payload
        const matches = Array.from(p.payload.matchAll(/([a-z0-9\-]{2,}\.[a-z]{2,})/gi)).map(m => m[1].toLowerCase());
        for (const d of matches) {
          const set = domainsBySrc.get(p.srcIP) ?? new Set<string>();
          set.add(d);
          domainsBySrc.set(p.srcIP, set);
          // DGA pattern match
          if (this.dgaPatterns.some(rx => rx.test(d))) {
            alerts.push({
              id: `dga_${p.srcIP}_${Date.now()}`,
              severity: 'high',
              type: 'dns_anomaly',
              timestamp: Date.now(),
              sourceIP: p.srcIP,
              description: `Suspicious DNS query likely DGA: ${d}`,
              affectedPackets: 1,
              evidence: [`Domain matched DGA pattern: ${d}`],
              related: [{ ip: p.srcIP }]
            });
          }
        }
      }
    }

    // Many unique domains in short period -> possible tunneling or beaconing
    for (const [src, set] of domainsBySrc.entries()) {
      if (set.size >= 100) {
        alerts.push({
          id: `dns_many_${src}_${Date.now()}`,
          severity: 'high',
          type: 'dns_anomaly',
          timestamp: Date.now(),
          sourceIP: src,
          description: `High number of unique DNS queries (${set.size}) from host`,
          affectedPackets: set.size,
          evidence: [`Unique domains: ${set.size}`, `Example: ${Array.from(set).slice(0, 5).join(', ')}`],
          related: [{ ip: src }]
        });
      }
    }

    return alerts;
  }

  // Protocol anomalies like malformed packets (basic heuristics)
  private detectProtocolAnomalies(packets: Packet[]): ThreatAlert[] {
    const alerts: ThreatAlert[] = [];
    for (const p of packets) {
      if (p.protocol === 'TCP' && p.length < 40 && p.payload && p.payload.length > 0 && p.flags?.length === 0) {
        alerts.push({
          id: `proto_${p.id ?? Date.now()}`,
          severity: 'medium',
          type: 'protocol_anomaly',
          timestamp: Date.now(),
          sourceIP: p.srcIP,
          description: `Suspicious TCP packet with small length and no flags`,
          affectedPackets: 1,
          evidence: [`Length: ${p.length}`, `Has payload: ${p.payload?.slice(0, 60)}`],
          related: [{ ip: p.srcIP }]
        });
      }
    }
    return alerts;
  }

  private isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(n => Number(n));
    if (parts.length !== 4 || parts.some(Number.isNaN)) return false;
    const [a, b] = parts;
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      ip === '127.0.0.1'
    );
  }
}