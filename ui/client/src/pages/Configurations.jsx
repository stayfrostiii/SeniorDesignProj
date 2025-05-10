import { useState } from "react";

export default function Configurations() {
  const [ip, setIp] = useState("");

  const handleAddToBlacklist = async () => {
    if (!ip) {
      alert("Please enter a valid IP address.");
      return;
    }
  
    // Validate IP address
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$/;
  
    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
      alert("Please enter a valid IPv4 or IPv6 address.");
      return;
    }
  
    try {
      const response = await fetch("http://127.0.0.1:8080/add-to-blacklist", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ip }),
      });
  
      if (response.ok) {
        alert(`IP ${ip} added to blacklist successfully.`);
        setIp(""); // Clear the input field
      } else {
        alert("Failed to add IP to blacklist.");
      }
    } catch (error) {
      console.error("Error adding IP to blacklist:", error);
      alert("An error occurred. Please try again.");
    }
  };

  return (
    <div className="grid-2x2 page-container">
      <div className="grid-item">
        <h2>Rules</h2>
        <p>Define rules for packet filtering.</p>
      </div>
      <div className="grid-item">
        <h2>Modify Performance vs. Efficiency</h2>
        <p>Adjust performance settings.</p>
      </div>
      <div className="grid-item">
        <h2>IP/URL Blacklist</h2>
        <p>Manage blacklisted IPs and URLs.</p>
        <input
          type="text"
          placeholder="Enter IP address"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          style={{
            padding: "10px",
            margin: "10px 0",
            width: "100%",
            borderRadius: "5px",
            border: "1px solid #ccc",
          }}
        />
        <button
          onClick={handleAddToBlacklist}
          style={{
            padding: "10px 20px",
            backgroundColor: "#007bff",
            color: "#fff",
            border: "none",
            borderRadius: "5px",
            cursor: "pointer",
          }}
        >
          Add to Blacklist
        </button>
      </div>
      <div className="grid-item">
        <h2>Application Blacklist</h2>
        <p>Manage blacklisted applications.</p>
      </div>
    </div>
  );
}