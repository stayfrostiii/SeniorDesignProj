export default function PacketWindow() {
  return (
    <div className="page-container" style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', height: '100%' }}>
      {/* Left Column: Packet List */}
      <div className="grid-item" style={{ gridRow: '1 / span 2' }}>
        <h2>Packet List</h2>
        <p>Displays packets (similar to Wireshark window).</p>
      </div>

      {/* Right Column: Packet Header Info */}
      <div className="grid-item">
        <h2>Packet Header Info</h2>
        <p>Details about the packet header.</p>
      </div>

      {/* Right Column: Packet Content Info */}
      <div className="grid-item">
        <h2>Packet Content Info</h2>
        <p>Details about the packet content.</p>
      </div>
    </div>
  );
}