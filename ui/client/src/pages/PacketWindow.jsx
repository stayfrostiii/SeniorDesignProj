import React, { useState, useEffect, useRef } from "react";

export default function PacketWindow() {
  const [packets, setPackets] = useState([]);
  const tableRef = useRef(null);

  useEffect(() => {
    // Connect to the /packet-stream endpoint using EventSource
    const eventSource = new EventSource("http://127.0.0.1:8080/packet-stream");

    eventSource.onmessage = (event) => {
      const packet = JSON.parse(event.data);

      // Add the new packet to the top of the list
      setPackets((prevPackets) => {
        const updatedPackets = [packet, ...prevPackets]; // Add new packet at the top
        if (updatedPackets.length > 50) {
          updatedPackets.pop(); // Remove the last packet if the list exceeds 50
        }
        return updatedPackets;
      });

      // Scroll to the top of the table for smooth updates (optional)
      if (tableRef.current) {
        tableRef.current.scrollTop = 0;
      }
    };

    eventSource.onerror = () => {
      console.error("Error connecting to the packet stream.");
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, []);

  return (
    <div
      className="grid-item" // Add the gray bounding box styling
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}
    >
      <h2>Packet List</h2>
      <div
        ref={tableRef}
        style={{
          maxHeight: "600px",
          overflowY: "auto",
          borderRadius: "5px",
          padding: "10px",
          backgroundColor: "#1e1e1e", // Match the dark theme
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            border: "1px solid #333", // Add grid lines
          }}
        >
          <thead>
            <tr>
              <th style={{ border: "1px solid #333" }}>Timestamp</th>
              <th style={{ border: "1px solid #333" }}>Source IP</th>
              <th style={{ border: "1px solid #333" }}>Destination IP</th>
              <th style={{ border: "1px solid #333" }}>Protocol</th>
              <th style={{ border: "1px solid #333" }}>Source Port</th>
              <th style={{ border: "1px solid #333" }}>Destination Port</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((packet, index) => (
              <tr key={index}>
                <td style={{ border: "1px solid #333" }}>{packet.timestamp}</td>
                <td style={{ border: "1px solid #333" }}>{packet.source_ip}</td>
                <td style={{ border: "1px solid #333" }}>{packet.dest_ip}</td>
                <td style={{ border: "1px solid #333" }}>{packet.protocol}</td>
                <td style={{ border: "1px solid #333" }}>{packet.source_port}</td>
                <td style={{ border: "1px solid #333" }}>{packet.dest_port}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}