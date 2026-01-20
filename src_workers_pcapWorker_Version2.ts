// src/workers/pcapWorker.ts
// Web Worker entrypoint: accepts ArrayBuffer and returns parsed packets (structured clone).
// Posts back { type: 'result', packets } or { type: 'error', message }.

import { PacketParser } from '../services/packetParser';

self.onmessage = (ev: MessageEvent) => {
  const { buffer } = ev.data as { buffer: ArrayBuffer };
  try {
    const parser = new PacketParser();
    let packets = parser.parsePCAP(buffer);
    if ((!packets || packets.length === 0) && typeof parser.parsePCAPNG === 'function') {
      packets = parser.parsePCAPNG(buffer);
    }
    (self as any).postMessage({ type: 'result', packets });
  } catch (err: any) {
    (self as any).postMessage({ type: 'error', message: err?.message || String(err) });
  }
};