from flask import Flask, request, jsonify
from flask_cors import CORS
import ipaddress

app = Flask(__name__)
cors = CORS(app, origins='*')

# In-memory storage for the blacklist
blacklist = set()  # Use a set for faster lookups and to avoid duplicates

@app.route("/api/users", methods=['GET'])
def users():
    return jsonify(
        {
            "users": [
                'arpan', 
                'zach',
                'jessie'
            ]
        }
    )

@app.route("/get-blacklist", methods=["GET"])
def get_blacklist():
    """Fetch the current blacklist."""
    return jsonify(list(blacklist)), 200  # Convert set to list for JSON serialization

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
        with open("/tmp/blacklist_pipe", "w") as pipe:
            pipe.write(ip)
        app.logger.info(f"IP {ip} added to blacklist.")
        blacklist.add(ip)  # Add IP to in-memory blacklist
        return jsonify({"message": f"IP {ip} added to blacklist successfully.", "blacklist": list(blacklist)}), 200
    except Exception as e:
        app.logger.error(f"Error writing to pipe: {e}")
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

    if ip in blacklist:
        try:
            # Optionally write to a named pipe or perform additional actions
            with open("/tmp/blacklist_pipe", "w") as pipe:
                pipe.write(f"REMOVE {ip}")
            app.logger.info(f"IP {ip} removed from blacklist.")
            
            blacklist.remove(ip)  # Remove IP from the in-memory set
            return jsonify({"message": f"IP {ip} removed from blacklist successfully.", "blacklist": list(blacklist)}), 200
        except Exception as e:
            app.logger.error(f"Error writing to pipe: {e}")
            return jsonify({"error": str(e)}), 500
    else:
        app.logger.error(f"IP address {ip} not found in blacklist.")
        return jsonify({"error": "IP address not found in blacklist"}), 404
    app.run(debug=True, port=8080)