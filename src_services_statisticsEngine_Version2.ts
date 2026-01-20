/* StatisticsEngine - creates aggregated metrics for UI visualizations.
   - Generates protocol distribution, top talkers, timeline buckets.
*/

import { Packet, NetworkStats } from '../types/security';

export class StatisticsEngine {
  generateStats(packets: Packet[]): NetworkStats {
    const uniqueIPs = new Set<string>();
    const protocolCounts = new Map<string, number>();
    const talkers = new Map<string, { packets: number; bytes: number }>();
    let minTime = Infinity;
    let maxTime = -Infinity;

    for (const p of packets) {
      uniqueIPs.add(p.srcIP);
      uniqueIPs.add(p.dstIP);

      protocolCounts.set(p.protocol, (protocolCounts.get(p.protocol) || 0) + 1);

      [p.srcIP, p.dstIP].forEach(ip => {
        if (!talkers.has(ip)) talkers.set(ip, { packets: 0, bytes: 0 });
        const s = talkers.get(ip)!;
        s.packets += 1;
        s.bytes += p.length;
      });

      minTime = Math.min(minTime, p.timestamp);
      maxTime = Math.max(maxTime, p.timestamp);
    }

    return {
      totalPackets: packets.length,
      uniqueIPs: uniqueIPs.size,
      protocolDistribution: Array.from(protocolCounts.entries())
        .map(([protocol, count]) => ({ protocol, count }))
        .sort((a, b) => b.count - a.count),
      topTalkers: Array.from(talkers.entries())
        .map(([ip, stats]) => ({ ip, packets: stats.packets, bytes: stats.bytes }))
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 20),
      timeRange: { start: minTime === Infinity ? Date.now() : minTime, end: maxTime === -Infinity ? Date.now() : maxTime }
    };
  }

  generateTimeline(packets: Packet[], bucketSizeMs = 60_000): { time: number; packets: number }[] {
    const buckets = new Map<number, number>();
    for (const p of packets) {
      const bucket = Math.floor(p.timestamp / bucketSizeMs) * bucketSizeMs;
      buckets.set(bucket, (buckets.get(bucket) || 0) + 1);
    }
    return Array.from(buckets.entries())
      .map(([time, count]) => ({ time, packets: count }))
      .sort((a, b) => a.time - b.time);
  }
}