// src/services/packetParser.ts
// Enhanced PCAP / PCAPNG parser with TCP seq/ack extraction and payloadBytes support.

import { Packet, Protocol } from '../types/security';

const IPV4 = (view: DataView, offset: number) =>
  Array.from({ length: 4 }, (_, i) => view.getUint8(offset + i)).join('.');

function tryDecodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const printable = (text.match(/[\x20-\x7E]/g)?.length ?? 0) / Math.max(1, text.length);
    if (printable > 0.5) return text;
  } catch {}
  return undefined;
}

export class PacketParser {
  parsePCAP(buffer: ArrayBuffer): Packet[] {
    const view = new DataView(buffer);
    if (view.byteLength < 24) throw new Error('PCAP too small');

    const magic = view.getUint32(0, false);
    const PCAP_BE = 0xa1b2c3d4;
    const PCAP_LE = 0xd4c3b2a1;
    const PCAP_NS_BE = 0xa1b23c4d;
    const PCAP_NS_LE = 0x4d3cb2a1;

    let littleEndian = false;
    if (magic === PCAP_LE || magic === PCAP_NS_LE) littleEndian = true;
    else if (magic === PCAP_BE || magic === PCAP_NS_BE) littleEndian = false;
    else throw new Error('Not a classic PCAP file');

    let offset = 24;
    const packets: Packet[] = [];

    while (offset + 16 <= view.byteLength) {
      const tsSec = view.getUint32(offset, littleEndian);
      const tsUsec = view.getUint32(offset + 4, littleEndian);
      const inclLen = view.getUint32(offset + 8, littleEndian);
      // const origLen = view.getUint32(offset + 12, littleEndian);

      offset += 16;
      if (offset + inclLen > view.byteLength) break;

      try {
        const p = this.parseEthernetFrame(view, offset, inclLen, tsSec * 1000 + Math.floor(tsUsec / 1000));
        if (p) packets.push(p);
      } catch (err) {
        console.warn('packet parse error', err);
      }

      offset += inclLen;
    }

    return packets;
  }

  parsePCAPNG(buffer: ArrayBuffer): Packet[] {
    const view = new DataView(buffer);
    const packets: Packet[] = [];
    let offset = 0;

    while (offset + 8 <= view.byteLength) {
      const blockType = view.getUint32(offset, true);
      const blockTotalLength = view.getUint32(offset + 4, true);
      if (blockTotalLength === 0 || offset + blockTotalLength > view.byteLength) break;

      try {
        if (blockType === 0x00000006 && blockTotalLength >= 28) {
          const tsHigh = view.getUint32(offset + 12, true);
          const tsLow = view.getUint32(offset + 16, true);
          const capLen = view.getUint32(offset + 20, true);
          const dataOffset = offset + 28;
          if (dataOffset + capLen <= offset + blockTotalLength) {
            const tsBig = (BigInt(tsHigh) << 32n) + BigInt(tsLow);
            let tsNumber = Number(tsBig);
            if (tsNumber > 4_000_000_000_000) tsNumber = Math.floor(tsNumber / 1_000_000);
            else if (tsNumber > 4_000_000) tsNumber = Math.floor(tsNumber / 1000);

            const p = this.parseEthernetFrame(view, dataOffset, capLen, tsNumber);
            if (p) packets.push(p);
          }
        }
      } catch (err) {
        console.warn('pcapng parse error', err);
      }

      offset += blockTotalLength;
    }

    return packets;
  }

  private parseEthernetFrame(view: DataView, offset: number, capturedLength: number, timestampMs: number): Packet | null {
    if (capturedLength < 14 || offset + 14 > view.byteLength) return null;

    const etherType = view.getUint16(offset + 12, false);
    if (etherType !== 0x0800) return null;

    const ipOffset = offset + 14;
    if (ipOffset + 20 > view.byteLength) return null;

    const verIhl = view.getUint8(ipOffset);
    const ihl = (verIhl & 0x0f) * 4;
    const protocolNum = view.getUint8(ipOffset + 9);
    const srcIP = IPV4(view, ipOffset + 12);
    const dstIP = IPV4(view, ipOffset + 16);

    const transportOffset = ipOffset + ihl;
    let srcPort = 0;
    let dstPort = 0;
    const flags: string[] = [];
    let payload: string | undefined;
    let payloadBytes: Uint8Array | undefined;
    let protocol: Protocol = 'OTHER';
    let seq: number | undefined;
    let ack: number | undefined;
    let window: number | undefined;

    try {
      if (protocolNum === 6 && transportOffset + 20 <= view.byteLength) {
        protocol = 'TCP';
        srcPort = view.getUint16(transportOffset, false);
        dstPort = view.getUint16(transportOffset + 2, false);
        seq = view.getUint32(transportOffset + 4, false);
        ack = view.getUint32(transportOffset + 8, false);
        const dataOffset = ((view.getUint8(transportOffset + 12) & 0xf0) >> 4) * 4;
        const flagsByte = view.getUint8(transportOffset + 13);
        if (flagsByte & 0x02) flags.push('SYN');
        if (flagsByte & 0x10) flags.push('ACK');
        if (flagsByte & 0x01) flags.push('FIN');
        if (flagsByte & 0x04) flags.push('RST');
        window = view.getUint16(transportOffset + 14, false);

        const payloadOffset = transportOffset + dataOffset;
        const payloadLen = Math.max(0, offset + capturedLength - payloadOffset);
        if (payloadLen > 0 && payloadOffset + payloadLen <= view.byteLength) {
          payloadBytes = new Uint8Array(view.buffer.slice(payloadOffset, payloadOffset + payloadLen));
          const txt = tryDecodeUtf8(payloadBytes);
          if (txt !== undefined) payload = txt;
          // Heuristic for HTTP
          if ((!payload && (dstPort === 80 || dstPort === 8080 || srcPort === 80)) || (payload && /HTTP\/\d\.\d|GET |POST |Host: /i.test(payload))) {
            protocol = 'HTTP';
          }
        }
      } else if (protocolNum === 17 && transportOffset + 8 <= view.byteLength) {
        protocol = 'UDP';
        srcPort = view.getUint16(transportOffset, false);
        dstPort = view.getUint16(transportOffset + 2, false);
        const payloadOffset = transportOffset + 8;
        const payloadLen = Math.max(0, offset + capturedLength - payloadOffset);
        if (payloadLen > 0 && payloadOffset + payloadLen <= view.byteLength) {
          payloadBytes = new Uint8Array(view.buffer.slice(payloadOffset, payloadOffset + payloadLen));
          const txt = tryDecodeUtf8(payloadBytes);
          if (txt !== undefined) payload = txt;
        }
        if (srcPort === 53 || dstPort === 53) protocol = 'DNS';
      } else if (protocolNum === 1) {
        protocol = 'ICMP';
      } else {
        protocol = 'OTHER';
      }
    } catch (err) {
      console.warn('transport parse error', err);
    }

    return {
      id: `${srcIP}:${srcPort}->${dstIP}:${dstPort}@${timestampMs}`,
      timestamp: timestampMs,
      srcIP,
      dstIP,
      srcPort,
      dstPort,
      protocol,
      length: capturedLength,
      flags,
      payload,
      payloadBytes,
      seq,
      ack,
      window,
      rawOffset: offset
    } as Packet;
  }

  // Simple CSV parser for local logs
  parseCSV(csvText: string): Packet[] {
    const rows = csvText.split(/\r?\n/).filter(Boolean);
    if (rows.length < 2) return [];

    const headers = rows[0].split(',').map(h => h.trim().toLowerCase());
    const out: Packet[] = [];

    for (let i = 1; i < rows.length; i++) {
      const cols = rows[i].split(',');
      if (cols.length < 2) continue;
      const row: Record<string, string> = {};
      headers.forEach((h, idx) => (row[h] = (cols[idx] ?? '').trim()));

      const ts = row['timestamp'] || row['time'] || row['ts'] || '';
      const timestamp = ts ? new Date(ts).getTime() : Date.now();

      const srcIP = row['source'] || row['src_ip'] || row['src'] || '';
      const dstIP = row['destination'] || row['dst_ip'] || row['dst'] || '';
      const srcPort = parseInt(row['source_port'] || row['src_port'] || '0') || 0;
      const dstPort = parseInt(row['destination_port'] || row['dst_port'] || '0') || 0;
      const protoRaw = (row['protocol'] || 'TCP').toUpperCase();
      const length = parseInt(row['length'] || row['size'] || '0') || 0;
      const flags = (row['flags'] || '').split('|').filter(Boolean);
      const payload = row['payload'] || undefined;

      const protocol = (['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP'].includes(protoRaw) ? (protoRaw as Protocol) : 'OTHER');

      out.push({
        id: `${srcIP}:${srcPort}->${dstIP}:${dstPort}@${timestamp}`,
        timestamp,
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        protocol,
        length,
        flags,
        payload
      });
    }

    return out;
  }

  parseJSON(text: string): Packet[] {
    try {
      const data = JSON.parse(text);
      if (!Array.isArray(data)) throw new Error('JSON must be an array of packet objects');
      return data.map((d: any, i: number) => ({
        id: d.id ?? `pkt_json_${i}`,
        timestamp: d.timestamp ? Number(d.timestamp) : new Date(d.time || Date.now()).getTime(),
        srcIP: d.src_ip || d.src || d.source_ip || d.source || '',
        dstIP: d.dst_ip || d.dst || d.destination_ip || d.destination || '',
        srcPort: Number(d.src_port || d.source_port || d.sport || 0) || 0,
        dstPort: Number(d.dst_port || d.destination_port || d.dport || 0) || 0,
        protocol: (d.protocol || 'TCP').toUpperCase() as Protocol,
        length: Number(d.length || d.size || 0) || 0,
        flags: d.flags || [],
        payload: d.payload,
        payloadBytes: d.payload_bytes ? new Uint8Array(d.payload_bytes) : undefined,
        seq: d.seq ? Number(d.seq) : undefined,
        ack: d.ack ? Number(d.ack) : undefined
      }));
    } catch {
      throw new Error('Invalid JSON packet log');
    }
  }
}