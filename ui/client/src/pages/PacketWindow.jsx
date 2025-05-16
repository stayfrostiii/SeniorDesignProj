import React, { useState, useEffect, useRef } from "react";

export default function PacketWindow() {
  const [packets, setPackets] = useState([]);
  const tableRef = useRef(null);

  useEffect(() => {
    const socket = new WebSocket('ws://10.0.0.100:8081');
    
    socket.onopen = () => console.log("WebSocket: connected");
    socket.onmessage = (event) => {
      const packet = JSON.parse(event.data);

      // Add the new packet to the top of the list
      setPackets((prevPackets) => {
        const updatedPackets = [packet, ...prevPackets]; // Add new packet at the top
        if (updatedPackets.length > 21) {
          updatedPackets.pop(); // Remove the last packet if the list exceeds 50
        }
        return updatedPackets;
      });

      // Scroll to the top of the table for smooth updates (optional)
      if (tableRef.current) {
        tableRef.current.scrollTop = 0;
      }
    };

    socket.onerror = (e) => {
      console.error("WebSocket: error", e);
    };
    socket.onclose = (e) => {
      console.warn("WebSocket: closed", e);
    };

    return () => {
      socket.close();
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
            tableLayout: "fixed",
            borderCollapse: "collapse",
            border: "1px solid #333", // Add grid lines
          }}
        >
          <thead>
            <tr>
              <th style={{ width: "20%", maxWidth: "20%", border: "1px solid #333" }}>Timestamp</th>
              <th style={{ width: "22%", maxWidth: "22%", border: "1px solid #333" }}>Source IP</th>
              <th style={{ width: "22%", maxWidth: "22%", border: "1px solid #333" }}>Destination IP</th>
              <th style={{ width: "12%", maxWidth: "12%", border: "1px solid #333" }}>Protocol</th>
              <th style={{ width: "12%", maxWidth: "12%", border: "1px solid #333" }}>Source Port</th>
              <th style={{ width: "12%", maxWidth: "12%", border: "1px solid #333" }}>Destination Port</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((packet, index) => (
              <tr key={index}>
                <td style={{ wordWrap: "break-word", whiteSpace: "normal", border: "1px solid #333" }}>{packet.time}</td>
                <td style={{ wordWrap: "break-word", whiteSpace: "normal", border: "1px solid #333" }}>{packet.src_ip}</td>
                <td style={{ wordWrap: "break-word", whiteSpace: "normal", border: "1px solid #333" }}>{packet.dest_ip}</td>
                <td style={{ wordWrap: "break-word", whiteSpace: "normal", border: "1px solid #333" }}>{packet.prot}</td>
                <td style={{ wordWrap: "break-word", whiteSpace: "normal", border: "1px solid #333" }}>{packet.src_port}</td>
                <td style={{ wordWrap: "break-word", whiteSpace: "normal", border: "1px solid #333" }}>{packet.dest_port}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}