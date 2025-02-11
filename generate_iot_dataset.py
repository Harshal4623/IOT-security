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
    """Generate simulated TLS encryption parameters."""
    return {
        "tls_version": random.choice(["TLSv1.2", "TLSv1.3"]),
        "cipher_suite": random.choice([
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256"
        ])
    }

def generate_authorization_info():
    """Generate simulated authorization details."""
    methods = ["SCRAM-SHA-256", "OAUTHBEARER", "PLAIN"]
    scopes = ["read", "write", "admin", "execute"]
    return {
        "auth_method": random.choice(methods),
        "token": random_string(20),
        "scopes": random.sample(scopes, k=random.randint(1, len(scopes)))
    }

def generate_client_certificate():
    """Generate simulated client certificate details."""
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
    """Generate simulated monitoring and logging information."""
    log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    log_messages = [
        "Connection established.",
        "Message processed successfully.",
        "Authentication failed.",
        "Certificate verified.",
        "Subscription accepted.",
        "Unexpected disconnect detected."
    ]
    return {
        "log_level": random.choice(log_levels),
        "log_message": random.choice(log_messages),
        "event_id": random_string(8),
        "source_ip": random_ip()
    }

def add_secure_protocol_info(component):
    """
    Add secure protocol fields (TLS info, authorization, client certificate,
    and monitoring/logging) to a component (e.g., a message or handshake).
    """
    component["tls_info"] = generate_tls_info()
    component["authorization"] = generate_authorization_info()
    component["client_certificate"] = generate_client_certificate()
    component["monitoring"] = generate_monitoring_info()
    return component

# ------------------ Application Field ------------------
# List of possible IoT application types.
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

# ------------------ MQTT Message & Handshake Generators ------------------

def generate_connect_message():
    """Simulate an MQTT CONNECT message with security details."""
    msg = {
        "timestamp": random_timestamp(),
        "message_type": "CONNECT",
        "client_id": random_string(10),
        "keepalive": random.randint(10, 120),
        "username": random_string(8),
        "password": random_string(12),
        "clean_session": random.choice([True, False])
    }
    return add_secure_protocol_info(msg)

def generate_publish_message():
    """Simulate an MQTT PUBLISH message with security details."""
    msg = {
        "timestamp": random_timestamp(),
        "message_type": "PUBLISH",
        "topic": f"topic/{random_string(5)}",
        "payload": random_string(random.randint(10, 50)),
        "qos": random.choice([0, 1, 2]),
        "retain": random.choice([True, False])
    }
    if msg["qos"] > 0:
        msg["message_id"] = random.randint(1, 65535)
    return add_secure_protocol_info(msg)

def generate_subscribe_message():
    """Simulate an MQTT SUBSCRIBE message with security details."""
    topics = []
    for _ in range(random.randint(1, 3)):
        topics.append({
            "topic": f"topic/{random_string(5)}",
            "qos": random.choice([0, 1, 2])
        })
    msg = {
        "timestamp": random_timestamp(),
        "message_type": "SUBSCRIBE",
        "message_id": random.randint(1, 65535),
        "topics": topics
    }
    return add_secure_protocol_info(msg)

def generate_disconnect_message():
    """Simulate an MQTT DISCONNECT message with security details."""
    msg = {
        "timestamp": random_timestamp(),
        "message_type": "DISCONNECT",
        "reason_code": random.choice([0, 1, 2, 3])
    }
    return add_secure_protocol_info(msg)

def generate_tls_handshake(client_role):
    """
    Simulate a TLS handshake sequence for a given client role (Publisher or Subscriber).
    Returns a list of handshake messages with security details.
    """
    now = datetime.datetime.utcnow()
    handshake = []
    
    # CLIENT_HELLO
    client_hello = {
        "timestamp": now.isoformat() + "Z",
        "message_type": f"{client_role}_CLIENT_HELLO",
        "client": client_role
    }
    handshake.append(add_secure_protocol_info(client_hello))
    
    # SERVER_HELLO
    server_hello = {
        "timestamp": (now + datetime.timedelta(milliseconds=50)).isoformat() + "Z",
        "message_type": f"{client_role}_SERVER_HELLO",
        "client": client_role
    }
    handshake.append(add_secure_protocol_info(server_hello))
    
    # SERVER_CERTIFICATE
    server_cert = {
        "timestamp": (now + datetime.timedelta(milliseconds=100)).isoformat() + "Z",
        "message_type": f"{client_role}_SERVER_CERTIFICATE",
        "client_certificate": generate_client_certificate(),
        "client": client_role
    }
    handshake.append(add_secure_protocol_info(server_cert))
    
    # SERVER_HELLO_DONE
    hello_done = {
        "timestamp": (now + datetime.timedelta(milliseconds=150)).isoformat() + "Z",
        "message_type": f"{client_role}_SERVER_HELLO_DONE",
        "client": client_role
    }
    handshake.append(add_secure_protocol_info(hello_done))
    
    # CLIENT_KEY_EXCHANGE
    key_exchange = {
        "timestamp": (now + datetime.timedelta(milliseconds=200)).isoformat() + "Z",
        "message_type": f"{client_role}_CLIENT_KEY_EXCHANGE",
        "key_exchange_info": random_string(64),
        "client": client_role
    }
    handshake.append(add_secure_protocol_info(key_exchange))
    
    # FINISHED
    finished = {
        "timestamp": (now + datetime.timedelta(milliseconds=250)).isoformat() + "Z",
        "message_type": f"{client_role}_FINISHED",
        "verification_data": random_string(32),
        "client": client_role
    }
    handshake.append(add_secure_protocol_info(finished))
    
    return handshake

def generate_publisher_session():
    """
    Generate a Publisher session including:
      - TLS handshake
      - CONNECT message
      - PUBLISH message
      - DISCONNECT message
    Returns the publisher session (a dictionary) and the published message.
    """
    publisher = {}
    publisher["handshake"] = generate_tls_handshake("Publisher")
    publisher["connect"] = generate_connect_message()
    pub_message = generate_publish_message()
    publisher["publish"] = pub_message
    publisher["disconnect"] = generate_disconnect_message()
    return publisher, pub_message

def generate_subscriber_session():
    """
    Generate a Subscriber session including:
      - TLS handshake
      - CONNECT message
      - SUBSCRIBE message
      - DISCONNECT message
    Returns the subscriber session (a dictionary) and the subscribe message.
    """
    subscriber = {}
    subscriber["handshake"] = generate_tls_handshake("Subscriber")
    subscriber["connect"] = generate_connect_message()
    subscribe_msg = generate_subscribe_message()
    subscriber["subscribe"] = subscribe_msg
    subscriber["disconnect"] = generate_disconnect_message()
    return subscriber, subscribe_msg

def generate_broker_session(publisher_handshake, subscriber_handshake, forwarded_message):
    """
    Generate a Broker session that logs both the Publisher and Subscriber handshake events
    and simulates forwarding the Publisher's message.
    """
    broker = {}
    broker["broker_id"] = "BROKER_" + random_string(8)
    broker["tls_info"] = generate_tls_info()
    broker["authorization"] = generate_authorization_info()
    broker["client_certificate"] = generate_client_certificate()
    broker["monitoring"] = generate_monitoring_info()
    broker["publisher_handshake"] = publisher_handshake
    broker["subscriber_handshake"] = subscriber_handshake
    broker["forwarded_message"] = forwarded_message
    return broker

def generate_complete_secure_mqtt_session():
    """
    Combine the Publisher, Subscriber, and Broker sessions into a complete secure MQTT session.
    An extra field 'application' is added to indicate the intended IoT application.
    Returns a dictionary representing the entire session.
    """
    session_id = random_string(12)
    session_start = datetime.datetime.utcnow().isoformat() + "Z"
    
    publisher_session, pub_message = generate_publisher_session()
    subscriber_session, _ = generate_subscriber_session()
    broker_session = generate_broker_session(
        publisher_session["handshake"],
        subscriber_session["handshake"],
        pub_message
    )
    
    # Choose an application type for this session.
    application = random.choice(APPLICATION_TYPES)
    
    session_end = datetime.datetime.utcnow().isoformat() + "Z"
    complete_session = {
        "session_id": session_id,
        "session_start": session_start,
        "session_end": session_end,
        "application": application,
        "broker": broker_session,
        "publisher": publisher_session,
        "subscriber": subscriber_session
    }
    return complete_session

def generate_session_files(num_sessions=1000, output_folder="secure_mqtt_sessions"):
    """
    Generate 'num_sessions' complete secure MQTT session files.
    Each session is saved as a separate JSON file in the specified output folder.
    """
    os.makedirs(output_folder, exist_ok=True)
    for i in range(num_sessions):
        session_data = generate_complete_secure_mqtt_session()
        filename = os.path.join(output_folder, f"session_{i+1}.json")
        with open(filename, "w") as f:
            json.dump(session_data, f, indent=2)
    print(f"Generated {num_sessions} session files in the '{output_folder}' folder.")

def main():
    generate_session_files(num_sessions=1000)

if __name__ == "__main__":
    main()
