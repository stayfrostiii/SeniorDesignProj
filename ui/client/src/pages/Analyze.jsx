import React, { useState, useEffect } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, BarChart, Bar, PieChart, Pie, Cell } from "recharts";

export default function Analyze() {
  const [packets, setPackets] = useState([]);
  const [performanceMetrics, setPerformanceMetrics] = useState({
    totalPackets: 0,
    avgProcessingTime: 0,
    dropRate: 0,
  });
  const [trafficVolume, setTrafficVolume] = useState([]);
  const [topTalkers, setTopTalkers] = useState({ sourceIPs: [], destinationIPs: [] });

  useEffect(() => {
    // Connect to the WebSocket server
    const socket = new WebSocket("ws://0.0.0.0:8081");

    socket.onmessage = (event) => {
      const packet = JSON.parse(event.data);

      // Add the new packet to the state
      setPackets((prevPackets) => {
        const updatedPackets = [packet, ...prevPackets];
        if (updatedPackets.length > 1000) updatedPackets.pop(); // Limit to 1000 packets
        return updatedPackets;
      });
    };

    return () => {
      socket.close();
    };
  }, []);

  useEffect(() => {
    // Calculate performance metrics
    const totalPackets = packets.length;
    const dropRate = packets.filter((p) => p.prot === "DROP").length / totalPackets || 0;
    const avgProcessingTime = Math.random() * 10; // Simulated value

    setPerformanceMetrics({
      totalPackets,
      avgProcessingTime: avgProcessingTime.toFixed(2),
      dropRate: (dropRate * 100).toFixed(2),
    });

    // Calculate traffic volume grouped by minute
    const volume = packets.reduce((acc, packet) => {
      const time = packet.time.split(" ")[1]; // Extract time (e.g., HH:MM:SS)
      const minute = time.slice(0, 5); // Extract HH:MM (minute-level granularity)
      acc[minute] = (acc[minute] || 0) + 1;
      return acc;
    }, {});
    setTrafficVolume(Object.entries(volume).map(([minute, count]) => ({ minute, count })));

    // Calculate top talkers
    const sourceCounts = packets.reduce((acc, packet) => {
      acc[packet.src_ip] = (acc[packet.src_ip] || 0) + 1;
      return acc;
    }, {});
    const destinationCounts = packets.reduce((acc, packet) => {
      acc[packet.dest_ip] = (acc[packet.dest_ip] || 0) + 1;
      return acc;
    }, {});
    setTopTalkers({
      sourceIPs: Object.entries(sourceCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
      destinationIPs: Object.entries(destinationCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
    });
  }, [packets]);

  useEffect(() => {
    let packetCount = 0;
    const queue = []; // Queue to store the last 30 seconds of data

    // Connect to the WebSocket server
    const socket = new WebSocket("ws://0.0.0.0:8081");

    // Increment packet count for each received packet
    socket.onmessage = () => {
      packetCount++;
    };

    // Update traffic volume every second
    const interval = setInterval(() => {
      const now = new Date();
      const currentTime = now.toTimeString().split(" ")[0]; // Format as HH:MM:SS

      // Add the current packet count to the queue
      if (queue.length >= 30) {
        queue.shift(); // Remove the oldest entry if the queue is full
      }
      queue.push({ time: currentTime, count: packetCount });

      // Update the state with the current queue
      setTrafficVolume((prevVolume) => {
        const updatedVolume = [...queue];
        packetCount = 0; // Reset packet count after state update
        return updatedVolume;
      });
    }, 1000);

    // Cleanup on component unmount
    return () => {
      clearInterval(interval);
      socket.close();
    };
  }, []);

  return (
    <div className="page-container page-container-2x2">

        <div className="grid-item">
          <h2>Performance Metrics</h2>
          <div style={{ display: "flex", justifyContent: "space-around", marginTop: "20px" }}>
            <div>
          <h3>Total Packets</h3>
          <p>{performanceMetrics.totalPackets}</p>
            </div>
            <div>
          <h3>Avg Processing Time</h3>
          <p>{performanceMetrics.avgProcessingTime} ms</p>
            </div>
            <div>
          <h3>Drop Rate</h3>
          <p>{performanceMetrics.dropRate}%</p>
            </div>
          </div>
        </div>

        {/* Traffic Volume Analysis */}
        <div className="grid-item">
          <h2>Traffic Volume Over Time</h2>
          {(() => {
            const gridItemWidth = document.querySelector(".grid-item")?.offsetWidth || 700;
            const lineChartWidth = gridItemWidth * 0.9;
            return (
          <LineChart
            width={lineChartWidth}
            height={300}
            data={trafficVolume}
            margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis
              dataKey="time"
              label={{ value: "Time (HH:MM:SS)", position: "insideBottom", offset: -5 }}
              tick={{ fontSize: 12 }}
            />
            <YAxis label={{ value: "Packets", angle: -90, position: "insideLeft" }} />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="count" stroke="#8884d8" activeDot={{ r: 8 }} />
          </LineChart>
            );
          })()}
        </div>
      <div className="grid-item">
        <h2>Top Talkers (Source IPs)</h2>
        {(() => {
          const gridItemWidth = document.querySelector(".grid-item")?.offsetWidth || 700;
          const barChartWidth = gridItemWidth * 0.9;
          return (
            <BarChart
              width={barChartWidth}
              height={300}
              data={topTalkers.sourceIPs}
              margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="ip" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#82ca9d" />
            </BarChart>
          );
        })()}
      </div>

      <div className="grid-item" style={{ display: "flex", justifyContent: "center", alignItems: "center" }}>
        <div>
          <h2 style={{ textAlign: "center" }}>Top Talkers (Destination IPs)</h2>
          <PieChart width={400} height={300}>
            <Pie
              data={topTalkers.destinationIPs}
              dataKey="count"
              nameKey="ip"
              cx="50%"
              cy="50%"
              outerRadius={100}
              fill="#8884d8"
              label
            >
              {topTalkers.destinationIPs.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={["#0088FE", "#00C49F", "#FFBB28", "#FF8042"][index % 4]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </div>
      </div>
    </div>
  );
}