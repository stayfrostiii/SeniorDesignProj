import { useState, useEffect } from "react";

export default function Configurations() {
  const [ip, setIp] = useState("");
  const [blacklist, setBlacklist] = useState([]);
  const [sourceIp, setSourceIp] = useState("");
  const [destinationIp, setDestinationIp] = useState("");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("");
  const [rules, setRules] = useState([]);

  // Fetch blacklist rules from the backend
  useEffect(() => {
    const fetchBlacklist = async () => {
      try {
        const response = await fetch("http://127.0.0.1:8080/get-blacklist");
        if (response.ok) {
          const data = await response.json();
          setBlacklist(data.blacklist); // Extract the "blacklist" key
        } else {
          console.error("Failed to fetch blacklist.");
        }
      } catch (error) {
        console.error("Error fetching blacklist:", error);
      }
    };

    fetchBlacklist();
  }, []);

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
        // Refresh the blacklist
        const updatedBlacklist = await response.json();
        setBlacklist(updatedBlacklist.blacklist); // Update the blacklist state
      } else {
        alert("Failed to add IP to blacklist.");
      }
    } catch (error) {
      console.error("Error adding IP to blacklist:", error);
      alert("An error occurred. Please try again.");
    }
  };

  const handleRemoveFromBlacklist = async (ipToRemove) => {
    try {
      const response = await fetch("http://127.0.0.1:8080/remove-from-blacklist", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ip: ipToRemove }),
      });

      if (response.ok) {
        alert(`IP ${ipToRemove} removed from blacklist successfully.`);
        // Refresh the blacklist
        const updatedBlacklist = await response.json();
        setBlacklist(updatedBlacklist);
      } else {
        alert("Failed to remove IP from blacklist.");
      }
    } catch (error) {
      console.error("Error removing IP from blacklist:", error);
      alert("An error occurred. Please try again.");
    }
  };

  const handleAddRule = async () => {
    if (!sourceIp || !destinationIp || !port || !protocol) {
      alert("Please fill out all fields.");
      return;
    }

    const newRule = { sourceIp, destinationIp, port, protocol };

    try {
      const response = await fetch("http://127.0.0.1:8080/add-rule", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(newRule),
      });

      if (response.ok) {
        const updatedRules = await response.json();
        setRules(updatedRules);
        setSourceIp("");
        setDestinationIp("");
        setPort("");
        setProtocol("");
      } else {
        alert("Failed to add rule.");
      }
    } catch (error) {
      console.error("Error adding rule:", error);
      alert("An error occurred. Please try again.");
    }
  };

  const handleRemoveRule = async (index) => {
    try {
      const response = await fetch("http://127.0.0.1:8080/remove-rule", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ index }),
      });

      if (response.ok) {
        const updatedRules = await response.json();
        setRules(updatedRules);
      } else {
        alert("Failed to remove rule.");
      }
    } catch (error) {
      console.error("Error removing rule:", error);
      alert("An error occurred. Please try again.");
    }
  };

  return (
    <div className="page-container page-container-3col">
      <div className="grid-item">
        <h2>IP/URL Blacklist</h2>
        <p>Manage blacklisted IPs and URLs.</p>
        <input
          type="text"
          placeholder="Enter IP address"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          className="input-field"
        />
        <button onClick={handleAddToBlacklist} className="button">
          Add to Blacklist
        </button>
        <hr className="divider" />
        <div>
          <h3>Current Blacklist</h3>
          <div className="list-container">
            {blacklist.map((item, index) => (
              <div key={index} className="list-item">
                <span>{item}</span>
                <button
                  onClick={() => handleRemoveFromBlacklist(item)}
                  className="remove-button"
                >
                  X
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="grid-item">
        <h2>Rules</h2>
        <p>Define rules for packet filtering.</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAddRule();
          }}
          className="form-container"
        >
          <input
            type="text"
            placeholder="Source IP (e.g., 192.168.1.1)"
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            className="input-field"
          />
          <input
            type="text"
            placeholder="Destination IP (e.g., 10.0.0.1)"
            value={destinationIp}
            onChange={(e) => setDestinationIp(e.target.value)}
            className="input-field"
          />
          <input
            type="number"
            placeholder="Port (e.g., 80)"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            className="input-field"
          />
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            className="input-field"
          >
            <option value="">Select Protocol</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
          <button type="submit" className="button">
            Add Rule
          </button>
        </form>
        <hr className="divider" />
        <div>
          <h3>Current Rules</h3>
          <div className="list-container">
            {rules.map((rule, index) => (
              <div key={index} className="list-item">
                <span>
                  {rule.sourceIp} → {rule.destinationIp} | Port: {rule.port} |
                  Protocol: {rule.protocol}
                </span>
                <button
                  onClick={() => handleRemoveRule(index)}
                  className="remove-button"
                >
                  X
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="grid-item">
        <h2>Performance vs Efficiency</h2>
        <p>Sample</p>
      </div>
    </div>
  );
}