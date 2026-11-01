import React, { useMemo } from 'react';

type HexViewerProps = {
  bytes: Uint8Array;
  bytesPerRow?: number;
  showOffset?: boolean;
  onCopy?: (hex: string) => void;
};

export default function HexViewer({ bytes, bytesPerRow = 16, showOffset = true, onCopy }: HexViewerProps) {
  const rows = useMemo(() => {
    const out: { offset: number; hex: string; ascii: string }[] = [];
    for (let i = 0; i < bytes.length; i += bytesPerRow) {
      const slice = bytes.subarray(i, i + bytesPerRow);
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(slice)
        .map(b => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
        .join('');
      out.push({ offset: i, hex, ascii });
    }
    return out;
  }, [bytes, bytesPerRow]);

  const handleCopy = async () => {
    if (!navigator.clipboard) {
      if (onCopy) onCopy(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
      return;
    }
    try {
      await navigator.clipboard.writeText(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' '));
      if (onCopy) onCopy('copied');
    } catch {
      if (onCopy) onCopy('error');
    }
  };

  return (
    <div style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, "Roboto Mono", monospace', fontSize: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <div>Hex Viewer</div>
        <button onClick={handleCopy} style={{ background: '#0b1220', color: '#e6eef6', border: '1px solid #23303a', padding: '4px 8px', borderRadius: 6 }}>
          Copy Hex
        </button>
      </div>
      <div style={{ overflowX: 'auto', border: '1px solid #23303a', borderRadius: 8, padding: 12, background: '#071024' }}>
        {rows.map((r, idx) => (
          <div key={idx} style={{ display: 'flex', gap: 12, padding: '2px 0' }}>
            {showOffset && <div style={{ width: 80, color: '#64748b' }}>{r.offset.toString(16).padStart(8, '0')}</div>}
            <div style={{ minWidth: 480, color: '#cbd5e1' }}>{r.hex}</div>
            <div style={{ color: '#94a3b8' }}>{r.ascii}</div>
          </div>
        ))}
      </div>
    </div>
  );
}