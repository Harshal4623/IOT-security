import os
import json
import random
import string
import datetime

# ------------------ Helper Functions ------------------

def random_string(length):
    """Generate a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_ip():
    """Generate a random IPv4 address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def random_timestamp():
    """Generate a random timestamp within the last 24 hours."""
    now = datetime.datetime.utcnow()
    offset = datetime.timedelta(seconds=random.randint(0, 86400))
    return (now - offset).isoformat() + "Z"

# ------------------ Secure Protocol Generators ------------------

def generate_tls_info():
    """Simulate TLS encryption parameters (for HTTPS)."""
    return {
        "tls_version": random.choice(["TLSv1.2", "TLSv1.3"]),
        "cipher_suite": random.choice([
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384"
        ])
    }

def generate_authorization_info():
    """Simulate authorization details."""
    methods = ["SCRAM-SHA-256", "OAUTHBEARER", "PLAIN"]
    scopes = ["read", "write", "admin", "execute"]
    return {
        "auth_method": random.choice(methods),
        "token": random_string(20),
        "scopes": random.sample(scopes, k=random.randint(1, len(scopes)))
    }

def generate_client_certificate():
    """Simulate client certificate details for certificate validation."""
    now = datetime.datetime.utcnow()
    past = now - datetime.timedelta(days=365)
    future = now + datetime.timedelta(days=365)
    return {
        "issuer": f"CA_{random_string(5)}",
        "subject": f"CN={random_string(8)}",
        "valid_from": past.isoformat() + "Z",
        "valid_to": future.isoformat() + "Z",
        "fingerprint": random_string(40)
    }

def generate_monitoring_info():
    """Simulate monitoring and logging information."""
    log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    log_messages = [
        "Connection established.",
        "Message processed successfully.",
        "Authentication failed.",
        "Certificate validated successfully.",
        "HSTS enforced.",
        "Unexpected disconnect detected."
    ]
    return {
        "log_level": random.choice(log_levels),
        "log_message": random.choice(log_messages),
        "event_id": random_string(8),
        "source_ip": random_ip()
    }

def generate_hsts_info():
    """Simulate HSTS header information."""
    return {
        "enabled": True,
        "max_age": 31536000,  # 1 year in seconds
        "includeSubDomains": True
    }

def add_secure_protocol_info(component):
    """
    Add secure protocol fields to a component:
      - HTTPS enabled flag
      - TLS info
      - Authorization details
      - Client certificate details
      - Monitoring/logging info
      - HSTS header settings
    """
    component["https_enabled"] = True
    component["tls_info"] = generate_tls_info()
    component["authorization"] = generate_authorization_info()
    component["client_certificate"] = generate_client_certificate()
    component["monitoring"] = generate_monitoring_info()
    component["HSTS"] = generate_hsts_info()
    return component

# ------------------ Application Field ------------------

APPLICATION_TYPES = [
    "Smart Home - Thermostat",
    "Smart Home - Light Bulb",
    "Smart Home - Security Camera",
    "Wearable Fitness Tracker",
    "Industrial Sensor",
    "Connected Car",
    "Agricultural Monitoring",
    "Medical Device - Glucose Meter",
    "Other Low-bandwidth IoT Device"
]

# ------------------ HTTP Request/Response Generators ------------------

def generate_http_request_message(method):
    """
    Generate an HTTP request message with secure protocol details.
    For POST and PUT, a JSON payload is included; GET and DELETE have no body.
    """
    req = {
        "timestamp": random_timestamp(),
        "method": method,
        "url": f"https://example.com/resource/{random_string(5)}",
        "headers": {
            "User-Agent": "SecureHTTPClient/1.0",
            "Accept": "application/json",
            "HSTS": "Enabled"
        }
    }
    if method in ["POST", "PUT"]:
        req["body"] = json.dumps({"data": random_string(random.randint(10, 50))})
        req["headers"]["Content-Type"] = "application/json"
    else:
        req["body"] = ""
    return add_secure_protocol_info(req)

def generate_http_response_message(method):
    """
    Generate an HTTP response message with secure protocol details.
    Standard status codes are used based on the request method.
    """
    status_codes = {
        "GET": 200,
        "POST": 201,
        "PUT": 200,
        "DELETE": 204
    }
    res = {
        "timestamp": random_timestamp(),
        "status_code": status_codes.get(method, 200),
        "headers": {
            "Content-Type": "application/json",
            "HSTS": "Enabled"
        }
    }
    if status_codes.get(method, 200) != 204:
        res["body"] = json.dumps({"result": random_string(random.randint(10, 30))})
    else:
        res["body"] = ""
    return add_secure_protocol_info(res)

# ------------------ HTTP Session Generator ------------------

def generate_complete_secure_http_session():
    """
    Generate a complete secure HTTP session containing one request/response for each HTTP method:
      GET, POST, PUT, and DELETE.
    The session also includes metadata (session_id, start/end timestamps) and an application field.
    """
    session_id = random_string(12)
    session_start = datetime.datetime.utcnow().isoformat() + "Z"
    
    methods = ["GET", "POST", "PUT", "DELETE"]
    messages = []
    for method in methods:
        request_msg = generate_http_request_message(method)
        response_msg = generate_http_response_message(method)
        messages.append({
            "request": request_msg,
            "response": response_msg
        })
    
    application = random.choice(APPLICATION_TYPES)
    session_end = datetime.datetime.utcnow().isoformat() + "Z"
    
    complete_session = {
        "session_id": session_id,
        "session_start": session_start,
        "session_end": session_end,
        "application": application,
        "messages": messages
    }
    return complete_session

# ------------------ Dataset Generation ------------------

def generate_session_files(num_sessions=1000, output_folder="secure_http_sessions"):
    """
    Generate 'num_sessions' complete secure HTTP session files.
    Each session is saved as a separate JSON file in the specified output folder.
    """
    os.makedirs(output_folder, exist_ok=True)
    for i in range(num_sessions):
        session_data = generate_complete_secure_http_session()
        filename = os.path.join(output_folder, f"session_{i+1}.json")
        with open(filename, "w") as f:
            json.dump(session_data, f, indent=2)
    print(f"Generated {num_sessions} session files in the '{output_folder}' folder.")

def main():
    generate_session_files(num_sessions=1000)

if __name__ == "__main__":
    main()
