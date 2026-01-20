import React, { useMemo, useState } from 'react';
import { TCPReassembler } from '../services/tcpReassembler';
import HexViewer from './HexViewer';
import { Packet } from '../types/security';

type StreamViewerProps = {
  packets: Packet[];
};

export default function StreamViewer({ packets }: StreamViewerProps) {
  const [selectedFlow, setSelectedFlow] = useState<string | null>(null);
  const [direction, setDirection] = useState<'c2s' | 's2c'>('c2s');

  // Build reassembler and streams
  const reassembler = useMemo(() => {
    const r = new TCPReassembler();
    r.ingestPackets(packets);
    return r;
  }, [packets]);

  const streams = useMemo(() => reassembler.getStreams(), [reassembler]);

  const selected = useMemo(() => {
    if (!selectedFlow) return null;
    return streams.find(s => s.flow === selectedFlow) ?? null;
  }, [selectedFlow, streams]);

  return (
    <div>
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 1 }}>
          <h3 style={{ marginTop: 0 }}>TCP Streams</h3>
          <div style={{ maxHeight: 420, overflowY: 'auto', border: '1px solid #23303a', borderRadius: 8, padding: 8 }}>
            {streams.map(s => (
              <div
                key={s.flow}
                onClick={() => setSelectedFlow(s.flow)}
                style={{
                  padding: 8,
                  borderRadius: 6,
                  marginBottom: 8,
                  background: s.flow === selectedFlow ? '#071b2a' : 'transparent',
                  cursor: 'pointer',
                  border: '1px solid #12232b'
                }}
              >
                <div style={{ fontSize: 13, color: '#cbd5e1' }}>
                  {s.flow} — segments: {s.segmentsCount} • {s.clientToServer.bytes.length}B ↔ {s.serverToClient.bytes.length}B
                </div>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>
                  Seen: {new Date(s.firstSeen).toLocaleString()} — {new Date(s.lastSeen).toLocaleString()}
                </div>
              </div>
            ))}
            {streams.length === 0 && <div style={{ color: '#64748b' }}>No reassemblable TCP streams with payload found</div>}
          </div>
        </div>

        <div style={{ flex: 2 }}>
          <h3 style={{ marginTop: 0 }}>Stream Detail</h3>
          {!selected && <div style={{ color: '#64748b' }}>Select a stream to inspect reassembled payloads and HTTP extraction.</div>}
          {selected && (
            <>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type="radio" checked={direction === 'c2s'} onChange={() => setDirection('c2s')} /> Client → Server
                </label>
                <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type="radio" checked={direction === 's2c'} onChange={() => setDirection('s2c')} /> Server → Client
                </label>
              </div>

              <div style={{ marginBottom: 12 }}>
                <strong>Flow:</strong> {selected.flow}
              </div>

              <div style={{ marginBottom: 12 }}>
                <strong>Completeness:</strong>{' '}
                {direction === 'c2s' ? (selected.clientToServer.complete ? 'complete' : `partial (${selected.clientToServer.missingBytes.length} holes)`) : selected.serverToClient.complete ? 'complete' : `partial (${selected.serverToClient.missingBytes.length} holes)`}
              </div>

              <div style={{ marginBottom: 12 }}>
                <strong>HTTP Messages</strong>
                <div style={{ marginTop: 8 }}>
                  {TCPReassembler.extractHTTPMessages(direction === 'c2s' ? selected.clientToServer.bytes : selected.serverToClient.bytes).length === 0 && (
                    <div style={{ color: '#64748b' }}>No HTTP-likely messages found</div>
                  )}
                  {TCPReassembler.extractHTTPMessages(direction === 'c2s' ? selected.clientToServer.bytes : selected.serverToClient.bytes).map((m, i) => (
                    <pre key={i} style={{ background: '#071024', padding: 8, borderRadius: 6, overflowX: 'auto', color: '#cbd5e1' }}>
                      {m.slice(0, 2000)}
                    </pre>
                  ))}
                </div>
              </div>

              <div>
                <strong>Hex / ASCII</strong>
                <div style={{ marginTop: 8 }}>
                  <HexViewer bytes={direction === 'c2s' ? selected.clientToServer.bytes : selected.serverToClient.bytes} />
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}