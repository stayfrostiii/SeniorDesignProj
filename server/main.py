from flask import Flask, request, jsonify
from flask_cors import CORS
import ipaddress
app = Flask(__name__)
cors = CORS(app, origins='*')

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
        return jsonify({"message": f"IP {ip} added to blacklist successfully."}), 200
    except Exception as e:
        app.logger.error(f"Error writing to pipe: {e}")
        return jsonify({"error": str(e)}), 500
if __name__ == "__main__":
    app.run(debug=True, port=8080)