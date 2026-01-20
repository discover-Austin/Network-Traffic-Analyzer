// src/services/geoip.ts
// Offline GeoIP mapper: loads CIDR/CSV, stores numeric ranges, binary-search lookup.
// No external requests. Expect user-supplied geo CSV (CIDR,country_code,country_name) or (start,end,country_code,country_name).

export interface GeoRange {
  start: number; // inclusive
  end: number; // inclusive
  countryCode: string;
  countryName?: string;
}

export class GeoIPMapper {
  private ranges: GeoRange[] = [];

  // Load from text (CSV). Supported formats:
  //  - cidr,country_code,country_name
  //  - start_ip,end_ip,country_code,country_name
  // Lines starting with # are ignored.
  loadFromCSV(text: string) {
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const parsed: GeoRange[] = [];

    for (const line of lines) {
      const parts = line.split(',').map(p => p.trim());
      if (parts.length >= 3) {
        if (parts[0].includes('/')) {
          // CIDR form
          try {
            const cidr = parts[0];
            const [start, end] = this.cidrToRange(cidr);
            parsed.push({
              start,
              end,
              countryCode: parts[1].toUpperCase(),
              countryName: parts[2] ?? parts[1]
            });
          } catch {
            continue;
          }
        } else if (parts.length >= 4 && this.isIP(parts[0]) && this.isIP(parts[1])) {
          parsed.push({
            start: this.ipToNumber(parts[0]),
            end: this.ipToNumber(parts[1]),
            countryCode: parts[2].toUpperCase(),
            countryName: parts[3]
          });
        } else {
          // Skip unknown format
          continue;
        }
      }
    }

    // Sort and merge overlapping ranges for faster lookup
    parsed.sort((a, b) => a.start - b.start);
    this.ranges = this.mergeRanges(parsed);
  }

  lookup(ip: string): GeoRange | null {
    if (!this.isIP(ip)) return null;
    const v = this.ipToNumber(ip);
    // Binary search across ranges
    let lo = 0;
    let hi = this.ranges.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const r = this.ranges[mid];
      if (v < r.start) hi = mid - 1;
      else if (v > r.end) lo = mid + 1;
      else return r;
    }
    return null;
  }

  // Helpers
  private ipToNumber(ip: string): number {
    const parts = ip.split('.').map(n => Number(n) || 0);
    return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
  }

  private isIP(ip: string): boolean {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
  }

  private cidrToRange(cidr: string): [number, number] {
    const [base, maskStr] = cidr.split('/');
    if (!this.isIP(base)) throw new Error('Invalid CIDR');
    const mask = Number(maskStr);
    const ipNum = this.ipToNumber(base);
    const maskBits = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
    const start = ipNum & maskBits;
    const end = start + ((~maskBits) >>> 0);
    return [start >>> 0, end >>> 0];
  }

  private mergeRanges(ranges: GeoRange[]): GeoRange[] {
    if (ranges.length === 0) return [];
    const out: GeoRange[] = [];
    let cur = { ...ranges[0] };
    for (let i = 1; i < ranges.length; i++) {
      const r = ranges[i];
      if (r.start <= cur.end + 1) {
        cur.end = Math.max(cur.end, r.end);
      } else {
        out.push(cur);
        cur = { ...r };
      }
    }
    out.push(cur);
    return out;
  }
}