from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# Dummy data for policies, logs, and alerts
policies = [
    {
        'id': 1,
        'application': 'bing.exe',
        'domain': 'instagram.com',
        'ip_address': '192.168.1.1',
        'protocol': 'TCP'
    }
]

logs = [
    {
        'timestamp': '2024-08-28 12:00:00',
        'application': 'youtube',
        'domain': 'youtube.com',
        'ip_address': '192.168.1.1',
        'protocol': 'TCP',
        'status': 'Allowed'
    },
    {
        'timestamp': '2024-08-28 12:00:00',
        'application': 'chrome.exe',
        'domain': 'instagram.com',
        'ip_address': '157.240.202.174',
        'protocol': 'TCP',
        'status': 'Allowed'
    }
]

alerts = [
    "Suspicious activity detected in TombRider",
    "Anomalous traffic from 192.168.1.100"
]

# Route to serve the dashboard
@app.route('/')
def dashboard():
    return render_template('index.html')

# API to get all policies
@app.route('/api/policies', methods=['GET'])
def get_policies():
    return jsonify(policies)

# API to add a new policy
@app.route('/api/policies', methods=['POST'])
def add_policy():
    new_policy = request.json
    new_policy['id'] = len(policies) + 1
    policies.append(new_policy)
    return jsonify({'message': 'Policy added successfully', 'policy': new_policy}), 201

# API to update an existing policy
@app.route('/api/policies/<int:policy_id>', methods=['PUT'])
def update_policy(policy_id):
    updated_policy = request.json
    for policy in policies:
        if policy['id'] == policy_id:
            policy.update(updated_policy)
            return jsonify({'message': 'Policy updated successfully', 'policy': policy})
    return jsonify({'message': 'Policy not found'}), 404


# API to delete a policy
@app.route('/api/policies/<int:policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    global policies
    policies = [policy for policy in policies if policy['id'] != policy_id]
    return jsonify({'message': 'Policy deleted successfully'}), 200

# API to get logs
@app.route('/api/logs', methods=['GET'])
def get_logs():
    return jsonify(logs)

# API to get alerts
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

@app.route('/api/alerts', methods=['POST'])
def add_alert():
    new_alert = request.json['alert']
    alerts.append(new_alert)
    return jsonify({'message': 'Alert added successfully', 'alert': new_alert}), 201

if __name__ == '__main__':
    app.run(debug=True)
