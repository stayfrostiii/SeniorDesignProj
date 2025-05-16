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
  const [currentFile, setCurrentFile] = useState('');
  const [error, setError] = useState(null);

  // Replace WebSocket with API polling
  useEffect(() => {
    // Initial fetch
    fetchData();
    
    // Set up polling interval
    const interval = setInterval(() => {
      fetchData();
    }, 2000); // Poll every 2 seconds
    
    // Clean up on unmount
    return () => clearInterval(interval);
  }, []);

  // Function to fetch data from backend
  const fetchData = async () => {
    try {
      const response = await fetch('http://10.0.0.100:8080/data');
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.error) {
        console.error("API Error:", data.error);
        setError(data.error);
        return;
      }
      
      // Update performance metrics
      if (data.performanceMetrics) {
        setPerformanceMetrics(data.performanceMetrics);
      }
      
      // Add new traffic volume data point
      if (data.trafficVolume) {
        setTrafficVolume(prevVolume => {
          const newVolume = [...prevVolume, data.trafficVolume];
          // Keep only the last 30 data points
          if (newVolume.length > 30) {
            return newVolume.slice(-30);
          }
          return newVolume;
        });
      }
      
      // Update top talkers
      if (data.topTalkers) {
        setTopTalkers(data.topTalkers);
      }
      
      // We still update the currentFile state but don't display it
      if (data.currentFile) {
        setCurrentFile(data.currentFile);
      }
      
      // Clear any previous error
      setError(null);
      
    } catch (err) {
      console.error("Failed to fetch data:", err);
      setError(`Failed to fetch data: ${err.message}`);
    }
  };

  return (
    <div className="page-container page-container-2x2">
      {/* Only show error messages, not current file */}
      {error && (
        <div style={{ gridColumn: "1 / -1", marginBottom: "20px" }}>
          <div className="file-info" style={{ borderColor: "#ff4d4f", backgroundColor: "#fff2f0" }}>
            <span style={{ color: "#ff4d4f" }}>Error: {error}</span>
          </div>
        </div>
      )}

      {/* Performance Metrics */}
      <div style={{ width: "100%", overflowX: "auto", padding: "1rem", boxSizing: "border-box" }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
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

          {/* Top Talkers (Source IPs) */}
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

          {/* Top Talkers (Destination IPs) */}
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
      </div>
    </div>
  );
}