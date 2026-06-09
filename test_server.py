#!/usr/bin/env python3
"""
SentinelShield Test Server
Uses the WAF Engine module for request inspection
"""

from flask import Flask, request, jsonify
from waf_engine import WAFEngine

app = Flask(__name__)
waf = WAFEngine()

@app.before_request
def waf_protection():
    """Inspect every request using WAF engine"""
    method = request.method
    path = request.path
    args = str(request.args)
    data = str(request.form) if request.form else ""
    ip = request.remote_addr
    
    allowed, reason = waf.analyze_request(method, path, args, data, ip)
    
    if not allowed:
        return jsonify({
            'status': 'BLOCKED',
            'reason': reason,
            'message': f'Request blocked by SentinelShield WAF: {reason}'
        }), 403

@app.route('/', methods=['GET', 'POST'])
def home():
    return jsonify({
        'status': 'OK',
        'message': 'SentinelShield WAF is protecting this server',
        'method': request.method
    }), 200

@app.route('/test', methods=['GET', 'POST'])
def test():
    param = request.args.get('param', 'none')
    return jsonify({
        'status': 'OK',
        'message': 'Test endpoint',
        'param': param
    }), 200

@app.route('/api/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return jsonify({
        'status': 'LOGIN_ATTEMPT',
        'username': username
    }), 200

@app.route('/api/stats', methods=['GET'])
def stats():
    waf.save_stats()
    return jsonify(waf.get_stats()), 200

@app.route('/api/report', methods=['GET'])
def report():
    waf.save_stats()
    return waf.generate_report(), 200, {'Content-Type': 'text/plain'}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'waf': 'active'}), 200

if __name__ == '__main__':
    print("="*70)
    print("SentinelShield Test Server - Part 2 (Enterprise Version)")
    print("="*70)
    print("WAF Engine: Active")
    print("Server: http://localhost:5000")
    print("Press CTRL+C to stop")
    print("="*70)
    
    waf.log_activity("=== SENTINELSHIELD TEST SERVER STARTED ===")
    app.run(host='0.0.0.0', port=5000, debug=False)
