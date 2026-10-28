from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/cloud/ingest", methods=["POST"])
def ingest():
    data = request.get_json()
    print(f"\n[MOCK CLOUD] Received telemetry payload: {data}")
    return jsonify({"status": "success", "message": "Mock cloud accepted payload"}), 200

if __name__ == "__main__":
    print("Starting Mock Cloud Server on http://127.0.0.1:5001 ...")
    app.run(host="127.0.0.1", port=5001)