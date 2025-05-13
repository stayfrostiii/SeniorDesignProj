export default function Analyze() {
  return (
    <div className="page-container page-container-2x2">
      <div className="grid-item">
        <h2>Dropped Packets</h2>
        <p>Information about dropped packets.</p>
      </div>
      <div className="grid-item">
        <h2>Suspicious Packets</h2>
        <p>Details about suspicious packets.</p>
      </div>
      <div className="grid-item">
        <h2>Performance</h2>
        <p>Performance metrics.</p>
      </div>
      <div className="grid-item">
        <h2>Packet Info</h2>
        <p>Details about selected packets.</p>
      </div>
    </div>
  );
}