"""
Sandbox API Server - REST endpoints for file upload and scanning
"""

import os
import json
import uuid
import logging
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from sandbox_engine import analyze_file

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SandboxAPI")

UPLOAD_DIR  = "/sandbox/uploads"
SAFE_DIR    = "/sandbox/safe"
REPORT_DIR  = "/sandbox/reports"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SAFE_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "Isolated Sandbox Engine"})

@app.route('/scan', methods=['POST'])
def scan_file():
    """Upload and scan a file in the sandbox"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    uploaded_file = request.files['file']
    if not uploaded_file.filename:
        return jsonify({"error": "No filename"}), 400
    
    # Save to upload directory with unique prefix
    safe_name = f"{uuid.uuid4().hex}_{uploaded_file.filename}"
    upload_path = os.path.join(UPLOAD_DIR, safe_name)
    
    try:
        uploaded_file.save(upload_path)
    except Exception as e:
        return jsonify({"error": f"Save failed: {str(e)}"}), 500
    
    # Run sandbox analysis
    try:
        report = analyze_file(upload_path, uploaded_file.filename)
        return jsonify(report)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route('/download/<md5>', methods=['GET'])
def download_safe_file(md5):
    """Download a file that was verified clean"""
    report_path = os.path.join(REPORT_DIR, f"{md5}.json")
    
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    
    with open(report_path) as f:
        report = json.load(f)
    
    if report.get("verdict") != "CLEAN":
        return jsonify({"error": "File is not clean - download blocked"}), 403
    
    dest = report.get("destination")
    if dest and os.path.exists(dest):
        return send_file(dest, as_attachment=True, download_name=report["filename"])
    
    return jsonify({"error": "File not found in safe storage"}), 404

@app.route('/reports', methods=['GET'])
def list_reports():
    """List all scan reports"""
    reports = []
    for fname in os.listdir(REPORT_DIR):
        if fname.endswith('.json'):
            with open(os.path.join(REPORT_DIR, fname)) as f:
                try:
                    r = json.load(f)
                    reports.append({
                        "filename": r.get("filename"),
                        "verdict": r.get("verdict"),
                        "risk_level": r.get("risk_level"),
                        "threat_score": r.get("threat_score"),
                        "timestamp": r.get("timestamp"),
                        "md5": r.get("hashes", {}).get("md5"),
                    })
                except Exception:
                    pass
    reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(reports)

@app.route('/report/<md5>', methods=['GET'])
def get_report(md5):
    """Get a specific scan report"""
    report_path = os.path.join(REPORT_DIR, f"{md5}.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path) as f:
        return jsonify(json.load(f))

if __name__ == '__main__':
    logger.info("Starting Sandbox API Server on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
