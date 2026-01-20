```markdown
# File Manifest — Network Traffic Analyzer (Additional Production Files)

These files are the complete, production-ready additions requested (Web Worker integration, offline GeoIP mapper, forensic hex viewer, TCP stream reassembly, and file manifest). All code runs client-side, requires no external APIs, and is TypeScript-first.

Files added/updated (paths are relative to repo root):

- src/types/security.ts
  - Enhanced packet type with TCP sequence/ack/window fields and stronger typing for downstream reassembly and forensic components.

- src/services/packetParser.ts
  - Robust PCAP / PCAPNG parser that extracts TCP sequence/ack numbers, flags, payloads, IPs/ports.
  - Safe fallbacks and defensive parsing; suitable to run inside a Web Worker.

- src/services/tcpReassembler.ts
  - Deterministic TCP stream reassembler handling out-of-order segments, retransmissions, overlapping segments, and missing bytes.
  - Produces ordered stream objects with completeness metadata and utilities to extract HTTP streams.

- src/services/geoip.ts
  - Offline GeoIP mapper.
  - Accepts a local CSV or newline-delimited CIDR list.
  - Efficient CIDR parsing, numeric-range storage, and binary-search lookup.
  - No external requests; designed to load a local GeoIP CSV (user-supplied).

- src/components/HexViewer.tsx
  - Production-quality hex/ASCII viewer component with selectable bytes, copy-to-clipboard, and configurable columns/bytes-per-row.

- src/components/StreamViewer.tsx
  - UI component to list reassembled TCP streams, preview reassembled payloads, extract HTTP requests/responses, and open a hex view for a stream.

- src/workers/pcapWorker.ts
  - Web Worker entrypoint for parsing large PCAP/PCAPNG buffers off the main thread; posts parsed packet arrays back to the main thread.

- src/App.tsx
  - Main application updated to:
    - Use the Web Worker automatically for files > 5MB.
    - Allow loading a local GeoIP CSV for geographic mapping (no external calls).
    - Provide StreamViewer and HexViewer integration for packet-level forensic inspection.
    - Keep all processing client-side.

- FILE_MANIFEST.md (this file)
  - This document.

Notes and usage:
- The GeoIP mapper expects a CSV with CIDR or start/end numeric ranges. No data is included in the repo to avoid shipping large GeoIP databases; you can load a vendor-provided CSV (e.g., derived from a licensed GeoIP file) using the UI.
- The Web Worker is written as a module; Vite builds it correctly via `new Worker(new URL('./workers/pcapWorker.ts', import.meta.url), { type: 'module' })`.
- All modules are written to be tree-shakable and unit-test friendly.

If you want, I can:
- Add unit tests for tcpReassembler (recommended).
- Add optional memory-pressure controls for very large files (streaming parse).
- Add an offline compact GeoIP sample generator to create a tiny demo DB (keeps repo small).
```