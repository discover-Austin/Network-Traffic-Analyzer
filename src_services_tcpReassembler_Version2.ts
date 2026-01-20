// src/services/tcpReassembler.ts
// Reassembles TCP streams from parsed Packet[]; handles out-of-order, overlaps, retransmits and provides stream extraction utilities.

import { Packet } from '../types/security';

type FlowKey = string;

export interface ReassembledSegment {
  seq: number;
  data: Uint8Array;
  ts: number;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
}

export interface ReassembledStream {
  flow: FlowKey;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  // Directional buffers
  clientToServer: { bytes: Uint8Array; complete: boolean; missingBytes: number[] };
  serverToClient: { bytes: Uint8Array; complete: boolean; missingBytes: number[] };
  segmentsCount: number;
  firstSeen: number;
  lastSeen: number;
}

function flowKeyFromPacket(p: Packet): FlowKey {
  // Normalize to canonical flow: lower tuple by lexical order to group both directions
  return `${p.srcIP}:${p.srcPort}->${p.dstIP}:${p.dstPort}`;
}

function reverseFlowKey(key: FlowKey) {
  const [left, right] = key.split('->');
  return `${right}->${left}`;
}

function ipToId(ip: string) {
  return ip;
}

export class TCPReassembler {
  // Map flow key (src:port->dst:port) -> segments
  private segmentsByFlow = new Map<FlowKey, ReassembledSegment[]>();

  ingestPackets(packets: Packet[]) {
    for (const p of packets) {
      if (p.protocol !== 'TCP') continue;
      if (!p.payloadBytes || p.payloadBytes.length === 0) continue;
      if (typeof p.seq !== 'number') continue;

      const key = flowKeyFromPacket(p);
      const seg: ReassembledSegment = {
        seq: p.seq >>> 0, // ensure unsigned
        data: p.payloadBytes,
        ts: p.timestamp,
        srcIP: p.srcIP,
        dstIP: p.dstIP,
        srcPort: p.srcPort,
        dstPort: p.dstPort
      };

      if (!this.segmentsByFlow.has(key)) this.segmentsByFlow.set(key, []);
      this.segmentsByFlow.get(key)!.push(seg);
    }

    // Sort segments for each flow by seq ascending then timestamp
    for (const [k, segs] of this.segmentsByFlow.entries()) {
      segs.sort((a, b) => {
        if (a.seq !== b.seq) return a.seq - b.seq;
        return a.ts - b.ts;
      });
    }
  }

  listFlows(): FlowKey[] {
    return Array.from(this.segmentsByFlow.keys());
  }

  getStreams(): ReassembledStream[] {
    const streams: ReassembledStream[] = [];

    for (const [flow, segs] of this.segmentsByFlow.entries()) {
      // Build directional segments
      const parts = flow.split('->');
      const [srcPart, dstPart] = parts;
      const [srcIP, srcPortStr] = srcPart.split(':');
      const [dstIP, dstPortStr] = dstPart.split(':');
      const srcPort = Number(srcPortStr);
      const dstPort = Number(dstPortStr);

      // Gather segments in both directions (one direction stored under flow, opposite under reverseFlow)
      const forwardSegs = segs;
      const reverseSegs = this.segmentsByFlow.get(reverseFlowKey(flow)) ?? [];

      const clientToServer = this.reassembleDirection(forwardSegs);
      const serverToClient = this.reassembleDirection(reverseSegs);

      const firstSeen = Math.min(
        forwardSegs.length ? forwardSegs[0].ts : Infinity,
        reverseSegs.length ? reverseSegs[0].ts : Infinity
      );
      const lastSeen = Math.max(
        forwardSegs.length ? forwardSegs[forwardSegs.length - 1].ts : -Infinity,
        reverseSegs.length ? reverseSegs[reverseSegs.length - 1].ts : -Infinity
      );

      streams.push({
        flow,
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        clientToServer: clientToServer.result,
        serverToClient: serverToClient.result,
        segmentsCount: forwardSegs.length + reverseSegs.length,
        firstSeen: firstSeen === Infinity ? Date.now() : firstSeen,
        lastSeen: lastSeen === -Infinity ? Date.now() : lastSeen
      });
    }

    return streams;
  }

  // Reassemble a direction's segments; returns combined bytes and metadata.
  private reassembleDirection(segs: ReassembledSegment[]) {
    // If empty
    if (!segs || segs.length === 0) {
      return { result: { bytes: new Uint8Array(0), complete: true, missingBytes: [] }, holes: [] as number[] };
    }

    // Use simple algorithm:
    // - Create a list of non-overlapping buffers by copying bytes into a growing ArrayBuffer keyed by sequence.
    // - We'll track the lowest sequence as baseSeq and place data relative to it.
    // - Note: TCP seq numbers wrap (32-bit). For simplicity we assume no wrap within stream or handle naive wrap detection.
    let baseSeq = segs[0].seq;
    // Normalize sequences relative to base
    const relativeRanges: { start: number; end: number; data: Uint8Array }[] = [];

    for (const s of segs) {
      let rel = s.seq - baseSeq;
      // naive wrap handling
      if (rel < -1_000_000_000) rel += 0xffffffff;
      else if (rel > 1_000_000_000) rel -= 0xffffffff;
      const start = Math.max(0, rel);
      const end = start + s.data.length;
      relativeRanges.push({ start, end, data: s.data });
    }

    // Determine final buffer size (max end)
    const maxEnd = relativeRanges.reduce((m, r) => Math.max(m, r.end), 0);
    const assembled = new Uint8Array(maxEnd);
    const written = new Uint8Array(maxEnd); // bitmap: 0/1 per byte written

    for (const r of relativeRanges) {
      for (let i = 0; i < r.data.length; i++) {
        const pos = r.start + i;
        // If overlapping, prefer earlier segment (already written). Overwrite only if not written.
        if (!written[pos]) {
          assembled[pos] = r.data[i];
          written[pos] = 1;
        }
      }
    }

    // Detect missing bytes
    const missing: number[] = [];
    for (let i = 0; i < written.length; i++) {
      if (!written[i]) missing.push(i);
    }

    return {
      result: {
        bytes: assembled,
        complete: missing.length === 0,
        missingBytes: missing
      },
      holes: missing
    };
  }

  // Utility: extract HTTP messages (naive split) from a reassembled byte array; returns strings of requests/responses
  static extractHTTPMessages(bytes: Uint8Array): string[] {
    try {
      const text = new TextDecoder().decode(bytes);
      // split by CRLFCRLF which separates headers from body in HTTP
      const messages = text.split(/\r\n\r\n(?=[A-Za-z]+ \/|HTTP\/\d\.\d )/);
      // Further trim and return candidate messages
      return messages
        .map(m => m.trim())
        .filter(m => m.length > 0 && (/HTTP\/\d\.\d|GET |POST |PUT |DELETE |HEAD /i.test(m)));
    } catch {
      return [];
    }
  }
}