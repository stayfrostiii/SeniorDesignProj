import { useState, useEffect } from "react";
import axios from "axios";

// Simple icon components
const ICONS = {
  log: <span title="Log Rule" style={{ marginLeft: 4 }}>📝</span>,
  rate: <span title="Rate Limited" style={{ marginLeft: 4 }}>🧮</span>,
};

function actionColor(action) {
  if (!action) return "";
  const a = action.toLowerCase();
  if (a === "allow") return "rule-allow";
  if (a === "drop" || a === "block") return "rule-block";
  if (a === "reject") return "rule-reject";
  return "";
}

export default function Configurations() {
  // Blacklist state and handlers (unchanged)
  const [ip, setIp] = useState("");
  const [blacklist, setBlacklist] = useState([]);

  // Rule manager state
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState({
    action: "allow",
    direction: "inbound",
    protocol: "TCP",
    source_ip: "",
    source_port: "",
    destination_ip: "",
    destination_port: "",
    interface: "",
    description: "",
    log: false,
    rate_limit: "",
  });
  const [editingId, setEditingId] = useState(null);
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);

  // Fetch blacklist rules from the backend
  useEffect(() => {
    const fetchBlacklist = async () => {
      try {
        const response = await fetch("http://10.0.0.100:8080/get-blacklist");
        if (response.ok) {
          const data = await response.json();
          setBlacklist(data.blacklist);
        }
      } catch (error) {
        console.error("Error fetching blacklist:", error);
      }
    };
    fetchBlacklist();
  }, []);

  // Fetch rules from backend
  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await axios.get("http://10.0.0.100:8080/rules");
      setRules(res.data); // Update the rules state with the data from the backend
    } catch (error) {
      console.error("Error fetching rules:", error);
    }
  };

  const handleSaveRule = async () => {
    try {
      if (editingId) {
        await axios.put(`http://10.0.0.100:8080/rules/${editingId}`, form);
      } else {
        await axios.post("http://10.0.0.100:8080/rules", form);
      }
      setForm({
        action: "allow",
        direction: "inbound",
        protocol: "TCP",
        source_ip: "",
        source_port: "",
        destination_ip: "",
        destination_port: "",
        interface: "",
        description: "",
        log: false,
        rate_limit: "",
      });
      setEditingId(null);
      setShowWizard(false);
      setWizardStep(0);
      fetchRules();
    } catch (error) {
      alert("Failed to save rule.");
    }
  };

  const handleDeleteRule = async (id) => {
    try {
      await axios.delete(`http://10.0.0.100:8080/rules/${id}`);
      fetchRules();
    } catch (error) {
      alert("Failed to delete rule.");
    }
  };

  // Blacklist handlers (unchanged)
  const handleAddToBlacklist = async () => {
    if (!ip) {
      alert("Please enter a valid IP address.");
      return;
    }
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$/;
    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
      alert("Please enter a valid IPv4 or IPv6 address.");
      return;
    }
    try {
      const response = await fetch("http://10.0.0.100:8080/add-to-blacklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (response.ok) {
        setIp("");
        const updatedBlacklist = await response.json();
        setBlacklist(updatedBlacklist.blacklist);
      } else {
        alert("Failed to add IP to blacklist.");
      }
    } catch (error) {
      alert("An error occurred. Fuck you Please try again.");
    }
  };

  const handleRemoveFromBlacklist = async (ipToRemove) => {
    try {
      const response = await fetch("http://10.0.0.100:8080/remove-from-blacklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ipToRemove }),
      });
      if (response.ok) {
        const updatedBlacklist = await response.json();
        setBlacklist(updatedBlacklist.blacklist); // Ensure the state is updated with the new blacklist
      } else {
        const errorData = await response.json();
        alert(errorData.error || "Failed to remove IP from blacklist.");
      }
    } catch (error) {
      console.error("Error removing IP from blacklist:", error);
      alert("An error occurred. Please try again.");
    }
  };

  // Wizard steps for rule builder
  const wizardFields = [
    {
      label: "What do you want to do?",
      field: "action",
      options: [
        { value: "allow", label: "✔️ Allow connections" },
        { value: "drop", label: "❌ Block connections" },
        { value: "reject", label: "↩️ Reject with message" },
        { value: "log", label: "📝 Log only" },
      ],
      type: "radio",
    },
    {
      label: "Direction of traffic",
      field: "direction",
      options: [
        { value: "inbound", label: "🔽 Inbound" },
        { value: "outbound", label: "🔼 Outbound" },
      ],
      type: "radio",
    },
    {
      label: "Protocol",
      field: "protocol",
      options: [
        { value: "TCP", label: "TCP" },
        { value: "UDP", label: "UDP" },
        { value: "ICMP", label: "ICMP" },
        { value: "ANY", label: "Any" },
      ],
      type: "radio",
    },
    {
      label: "Source IP",
      field: "source_ip",
      type: "text",
      placeholder: "e.g. 192.168.1.1 or Any",
    },
    {
      label: "Source Port",
      field: "source_port",
      type: "text",
      placeholder: "e.g. 80 or Any",
    },
    {
      label: "Destination IP",
      field: "destination_ip",
      type: "text",
      placeholder: "e.g. 10.0.0.1 or Any",
    },
    {
      label: "Destination Port",
      field: "destination_port",
      type: "text",
      placeholder: "e.g. 443 or Any",
    },
    {
      label: "Interface",
      field: "interface",
      type: "text",
      placeholder: "e.g. eth0 or Any",
    },
    {
      label: "Description",
      field: "description",
      type: "text",
      placeholder: "Optional description",
    },
    {
      label: "Log this rule?",
      field: "log",
      type: "checkbox",
    },
    {
      label: "Rate limit (optional)",
      field: "rate_limit",
      type: "text",
      placeholder: "e.g. 10/sec",
    },
  ];

  function renderWizardStep() {
    const step = wizardFields[wizardStep];
    if (!step) return null;
    if (step.type === "radio") {
      return (
        <div>
          <label style={{ fontWeight: "bold" }}>{step.label}</label>
          <div>
            {step.options.map(opt => (
              <label key={opt.value} style={{ marginRight: 16 }}>
                <input
                  type="radio"
                  name={step.field}
                  value={opt.value}
                  checked={form[step.field] === opt.value}
                  onChange={e => setForm({ ...form, [step.field]: e.target.value })}
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>
      );
    }
    if (step.type === "checkbox") {
      return (
        <div>
          <label>
            <input
              type="checkbox"
              checked={!!form[step.field]}
              onChange={e => setForm({ ...form, [step.field]: e.target.checked })}
            />
            {step.label}
          </label>
        </div>
      );
    }
    // text input
    return (
      <div>
        <label style={{ fontWeight: "bold" }}>{step.label}</label>
        <input
          type="text"
          placeholder={step.placeholder || ""}
          value={form[step.field] || ""}
          onChange={e => setForm({ ...form, [step.field]: e.target.value })}
          className="input-field"
        />
      </div>
    );
  }

  return (
    <div className="page-container custom-2col-split">
      {/* Blacklist section on the left */}
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
      {/* Rules section on the right */}
      <div className="grid-item">
        <h2>Firewall Rules</h2>
        <button
          className="button"
          style={{ marginBottom: "1em" }}
          onClick={() => {
            setForm({
              action: "allow",
              source_ip: "",
              source_port: "",
              destination_ip: "",
              destination_port: "",
              log: false,
              rate_limit: "",
            });
            setEditingId(null);
            setShowWizard(true);
            setWizardStep(0);
          }}
        >
          Add Rule
        </button>
        <table border="1" style={{ width: "100%", marginBottom: "1em" }}>
          <thead>
            <tr>
              <th>#</th>
              <th>Action</th>
              <th>Source IP</th>
              <th>Source Port</th>
              <th>Destination IP</th>
              <th>Destination Port</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, idx) => (
              <tr key={rule.id}>
                <td>{idx + 1}</td>
                <td className={actionColor(rule.action)}>{rule.action}</td>
                <td>{rule.source_ip}</td>
                <td>{rule.source_port}</td>
                <td>{rule.destination_ip}</td>
                <td>{rule.destination_port}</td>
                <td>
                  <button
                    onClick={() => {
                      setForm(rule);
                      setEditingId(rule.id);
                      setShowWizard(true);
                      setWizardStep(0);
                    }}
                  >
                    Edit
                  </button>
                  <button onClick={() => handleDeleteRule(rule.id)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {/* Rule Builder Wizard Modal */}
        {showWizard && (
          <div className="modal-overlay">
            <div className="modal-content">
              <form
                onSubmit={e => {
                  e.preventDefault();
                  if (wizardStep < wizardFields.length - 1) {
                    setWizardStep(wizardStep + 1);
                  } else {
                    handleSaveRule();
                  }
                }}
              >
                <h3>{editingId ? "Edit Rule" : "Add Rule"}</h3>
                {renderWizardStep()}
                <div style={{ marginTop: 16 }}>
                  {wizardStep > 0 && (
                    <button
                      type="button"
                      className="button"
                      onClick={() => setWizardStep(wizardStep - 1)}
                      style={{ marginRight: 8 }}
                    >
                      Back
                    </button>
                  )}
                  <button type="submit" className="button">
                    {wizardStep < wizardFields.length - 1 ? "Next" : "Save"}
                  </button>
                  <button
                    type="button"
                    className="button"
                    style={{ marginLeft: 8 }}
                    onClick={() => {
                      setShowWizard(false);
                      setEditingId(null);
                      setWizardStep(0);
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}