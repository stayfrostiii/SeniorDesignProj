from flask import Flask, request, jsonify
from flask_cors import CORS
import ipaddress
import subprocess
from uuid import uuid4

app = Flask(__name__)
cors = CORS(app, origins='*')

# In-memory storage for the blacklist and rules
blacklist = set()  # Use a set for faster lookups and to avoid duplicates
rules = []

@app.route("/get-blacklist", methods=["GET"])
def get_blacklist():
    """Fetch the current blacklist from nftables."""
    try:
        # Run the Linux command to list the nftables rules
        command = "sudo nft list ruleset"
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse the output to extract blacklisted IPs
        blacklisted_ips = []
        for line in result.stdout.splitlines():
            if "ip saddr" in line and "drop" in line:  # Look for rules with "ip saddr" and "drop"
                parts = line.split()
                ip_index = parts.index("ip") + 2  # The IP address is two words after "ip"
                blacklisted_ips.append(parts[ip_index])

        app.logger.info("Fetched blacklist from nftables.")
        return jsonify({"blacklist": blacklisted_ips}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error fetching blacklist: {e}")
        return jsonify({"error": f"Failed to fetch blacklist: {e}"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/add-to-blacklist", methods=["POST"])
def add_to_blacklist():
    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        app.logger.error("No IP address provided.")
        return jsonify({"error": "IP address is required"}), 400

    try:
        ipaddress.ip_address(ip)  # Validate IP address
    except ValueError:
        app.logger.error(f"Invalid IP address: {ip}")
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        # Run the Linux command to blacklist the IP
        command = f"sudo nft add rule inet combined_table input_chain ip saddr {ip} drop"
        subprocess.run(command, shell=True, check=True)

        app.logger.info(f"IP {ip} added to blacklist via nftables.")
        blacklist.add(ip)  # Add IP to in-memory blacklist
        return jsonify({"message": f"IP {ip} added to blacklist successfully.", "blacklist": list(blacklist)}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error running command: {e}")
        return jsonify({"error": f"Failed to add IP to blacklist: {e}"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route("/remove-from-blacklist", methods=["POST"])
def remove_from_blacklist():
    """Remove an IP address from the blacklist."""
    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        app.logger.error("No IP address provided.")
        return jsonify({"error": "IP address is required"}), 400

    try:
        ipaddress.ip_address(ip)  # Validate IP address
    except ValueError:
        app.logger.error(f"Invalid IP address: {ip}")
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        # List the rules in the chain with handles
        command = "sudo nft -a list chain inet combined_table input_chain"
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse the output to find the rule handle
        rule_handle = None
        for line in result.stdout.splitlines():
            if f"ip saddr {ip} drop" in line:
                parts = line.split()
                # Find the word "handle" and extract the handle value
                if "handle" in parts:
                    handle_index = parts.index("handle") + 1
                    if handle_index < len(parts) and parts[handle_index].isdigit():
                        rule_handle = parts[handle_index]
                        break

        if not rule_handle:
            app.logger.error(f"Rule for IP {ip} not found in nftables.")
            return jsonify({"error": "IP address not found in blacklist"}), 404

        # Delete the rule using the handle
        command = f"sudo nft delete rule inet combined_table input_chain handle {rule_handle}"
        subprocess.run(command, shell=True, check=True)

        app.logger.info(f"IP {ip} removed from blacklist via nftables.")
        blacklist.discard(ip)  # Remove IP from in-memory set if it exists
        return jsonify({"message": f"IP {ip} removed from blacklist successfully.", "blacklist": list(blacklist)}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error running command: {e}")
        return jsonify({"error": f"Failed to remove IP from blacklist: {e}"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/rules", methods=["GET"])
def get_rules():
    return jsonify(rules)

@app.route("/rules", methods=["POST"])
def add_rule():
    data = request.json
    data["id"] = str(uuid4())
    rules.append(data)
    return jsonify(data), 201

@app.route("/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id):
    for rule in rules:
        if rule["id"] == rule_id:
            rule.update(request.json)
            return jsonify(rule)
    return jsonify({"error": "Rule not found"}), 404

@app.route("/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    global rules
    rules = [r for r in rules if r["id"] != rule_id]
    return "", 204

@app.route("/simulate", methods=["POST"])
def simulate_packet():
    packet = request.json
    # Naive simulation: just match source/destination IP/port
    for rule in rules:
        if (rule.get("source_ip", "any") == packet.get("source_ip", "any") or rule.get("source_ip", "any") == "any") and \
           (rule.get("destination_ip", "any") == packet.get("destination_ip", "any") or rule.get("destination_ip", "any") == "any"):
            return jsonify({"action": rule.get("action", "allow"), "matched_rule": rule})
    return jsonify({"action": "allow", "matched_rule": None})

if __name__ == "__main__":
    app.run(debug=True, port=8080)