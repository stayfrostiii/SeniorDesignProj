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
        command = "sudo nft -a list chain inet combined_table input_chain"
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse the output to extract blacklisted IPs
        blacklisted_ips = []
        for line in result.stdout.splitlines():
            if "ip saddr" in line and "drop" in line and "dport" not in line and "sport" not in line:
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

    # Check if a general rule already exists for this IP
    for rule in rules:
        if rule["source_ip"] == ip:
            app.logger.error(f"General rule already exists for IP {ip}.")
            return jsonify({"error": f"General rule already exists for IP {ip}. Remove it before adding to blacklist."}), 400

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
    """Fetch the current rules from nftables."""
    try:
        # Run the Linux command to list the nftables rules
        command = "sudo nft -a list chain inet combined_table input_chain"  # Use -a to include rule handles
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse the output to extract rules and their handles
        nft_rules = []
        for line in result.stdout.splitlines():
            if "ip saddr" in line and "drop" in line and "dport" not in line and "sport" not in line:
                # Skip blacklist rules
                continue
            if "ip saddr" in line:  # General rules
                parts = line.split()
                rule = {
                    "id": parts[parts.index("handle") + 1] if "handle" in parts else None,  # Extract the rule handle
                    "action": parts[0],  # Action (e.g., allow, drop, reject)
                    "source_ip": parts[parts.index("ip") + 2] if "ip" in parts else "any",
                    "destination_ip": parts[parts.index("daddr") + 1] if "daddr" in parts else "any",
                    "source_port": parts[parts.index("sport") + 1] if "sport" in parts else "any",
                    "destination_port": parts[parts.index("dport") + 1] if "dport" in parts else "any",
                }
                nft_rules.append(rule)

        app.logger.info("Fetched rules from nftables.")
        return jsonify(nft_rules), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error fetching rules: {e}")
        return jsonify({"error": f"Failed to fetch rules: {e}"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/rules", methods=["POST"])
def add_rule():
    data = request.json

    # Use "any" as the default for optional fields
    source_ip = data.get("source_ip", "any")
    destination_port = data.get("destination_port", "any")

    # Check if the rule matches the blacklist pattern
    if data["action"] == "drop" and destination_port == "any":
        app.logger.error("Blacklist rules must be added via /add-to-blacklist.")
        return jsonify({"error": "Blacklist rules must be added via /add-to-blacklist."}), 400

    try:
        # Add the rule to nftables
        command = f"sudo nft add rule inet combined_table input_chain ip saddr {source_ip}"
        if destination_port != "any":
            command += f" tcp dport {destination_port}"
        command += f" {data['action']}"  # Add the terminal action (e.g., drop, accept)
        subprocess.run(command, shell=True, check=True)

        # Retrieve the handle of the newly added rule
        list_command = "sudo nft -a list chain inet combined_table input_chain"
        result = subprocess.run(list_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse the output to find the handle of the newly added rule
        rule_handle = None
        for line in result.stdout.splitlines():
            if f"ip saddr {source_ip}" in line and (f"tcp dport {destination_port}" in line or "tcp dport" not in line):
                parts = line.split()
                if "handle" in parts:
                    handle_index = parts.index("handle") + 1
                    if handle_index < len(parts) and parts[handle_index].isdigit():
                        rule_handle = parts[handle_index]
                        break

        if not rule_handle:
            app.logger.error("Failed to retrieve handle for the newly added rule.")
            return jsonify({"error": "Failed to retrieve handle for the newly added rule"}), 500

        # Add the rule to the in-memory list with the handle as the ID
        data["id"] = rule_handle
        rules.append(data)

        return jsonify(data), 201
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error adding rule to nftables: {e}")
        return jsonify({"error": f"Failed to add rule to nftables: {e}"}), 500

@app.route("/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id):
    for rule in rules:
        if rule["id"] == rule_id:
            rule.update(request.json)
            return jsonify(rule)
    return jsonify({"error": "Rule not found"}), 404

@app.route("/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    try:
        # List the rules in the chain with handles
        command = "sudo nft -a list chain inet combined_table input_chain"
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse the output to find the rule handle that matches the rule_id
        rule_handle = None
        for line in result.stdout.splitlines():
            if f"handle {rule_id}" in line:  # Match the rule_id with the handle
                rule_handle = rule_id
                break

        if not rule_handle:
            app.logger.error(f"Rule with handle {rule_id} not found in nftables.")
            return jsonify({"error": "Rule not found in nftables"}), 404

        # Delete the rule using the handle
        delete_command = f"sudo nft delete rule inet combined_table input_chain handle {rule_handle}"
        subprocess.run(delete_command, shell=True, check=True)

        app.logger.info(f"Rule with handle {rule_handle} deleted from nftables.")
        return jsonify({"message": f"Rule with handle {rule_handle} deleted successfully."}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error deleting rule from nftables: {e}")
        return jsonify({"error": f"Failed to delete rule from nftables: {e}"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": str(e)}), 500

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
    app.run(host='0.0.0.0', port=8080, debug=True)