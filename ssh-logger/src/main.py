import re
import socket
import firebase_admin
from firebase_admin import credentials, firestore
import os




# Add firebase key here
key = {
}


# Define log file location
log_file_path = '/var/log/auth.log'
current_directory = os.path.dirname(os.path.abspath(__file__))
# log_file_path = os.path.join(current_directory, 'auth.log')

# Define regular expressions for different log types
valid_username_correct_password_pattern = re.compile(r'Accepted password for (\S+) from (\S+) port (\d+)')
valid_username_incorrect_password_pattern = re.compile(r'Failed password for (\S+) from (\S+) port (\d+)')
invalid_username_pattern = re.compile(r'Invalid user (\S+) from (\S+) port (\d+)')

# Updated regex to handle timestamp format with spaces
timestamp_pattern = re.compile(r'(\w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2})')

# Data storage for different buckets
valid_username_correct_password = []
valid_username_incorrect_password = []
invalid_username = []

# Get the hostname and IP address of the server
hostname = socket.gethostname()
server_ip = socket.gethostbyname(hostname)

# Firebase initialization
# file_path = os.path.join(current_directory, 'key.json')
cred = credentials.Certificate(key)
firebase_admin.initialize_app(cred)

# Firestore client
db = firestore.client()


def clear_firestore_collection(collection_name):
    collection_ref = db.collection(hostname)
    docs = collection_ref.stream()
    for doc in docs:
        doc.reference.delete()

    #db.collection("logs").document(hostname).delete()
    # print(f"Cleared all documents in the collection '{collection_name}'.")



# Function to process the logs and segregate them
def process_logs():
    with open(log_file_path, 'r') as file:
        for line in file:
            # Check for valid username with correct password
            match_valid_correct = valid_username_correct_password_pattern.search(line)
            if match_valid_correct:
                username, ip_address, port = match_valid_correct.groups()
                timestamp = extract_timestamp(line)
                valid_username_correct_password.append({
                    'timestamp': timestamp,
                    'ip_address': ip_address,
                    'port': port,
                    'username': username
                })
                continue

            # Check for valid username with incorrect password
            match_valid_incorrect = valid_username_incorrect_password_pattern.search(line)
            if match_valid_incorrect:
                username, ip_address, port = match_valid_incorrect.groups()
                timestamp = extract_timestamp(line)
                valid_username_incorrect_password.append({
                    'timestamp': timestamp,
                    'ip_address': ip_address,
                    'port': port,
                    'username': username
                })
                continue

            # Check for invalid username
            match_invalid = invalid_username_pattern.search(line)
            if match_invalid:
                username, ip_address, port = match_invalid.groups()
                timestamp = extract_timestamp(line)
                invalid_username.append({
                    'timestamp': timestamp,
                    'ip_address': ip_address,
                    'port': port,
                    'username': username
                })

# Helper function to extract timestamp from log line
def extract_timestamp(line):
    timestamp_match = timestamp_pattern.match(line)
    return timestamp_match.group(1) if timestamp_match else None

# Function to upload the data to Firebase
def upload_to_firebase():
    clear_firestore_collection('logs')

    entries_one = {}
    for entry in valid_username_correct_password:

        entries_one[entry['timestamp']]={
            
            'client_ip_address': entry['ip_address'],
            'client_port': entry['port'],
            'server_username': entry['username']
        }

    v_u_c_p = {"Valid Username Correct Password": entries_one}

    db.collection(hostname).document("Valid Username Correct Password").set(entries_one)
    
    # Upload valid username with incorrect password data
    entries_two = {}
    for entry in valid_username_incorrect_password:
        entries_two[entry['timestamp']]={
            
            'client_ip_address': entry['ip_address'],
            'client_port': entry['port'],
            'server_username': entry['username']
        }

    v_u_ic_p = {"Valid Username Incorrect Password": entries_two}

    db.collection(hostname).document("Valid Username Incorrect Password").set(entries_two)
    
    # Upload invalid username data
    entries_three = {}
    for entry in invalid_username:
        entries_three[entry['timestamp']]={
            
            'client_ip_address': entry['ip_address'],
            'client_port': entry['port'],
            'server_username': entry['username']
        }

    iv_u = {"Invalid Username": entries_three}

    

    db.collection(hostname).document("Invalid Username").set(entries_three)

# Function to print the logs in the required format
def print_buckets():
    print(f"\nServer Hostname: {hostname} | IP Address: {server_ip}")
    
    print("\n--- Valid Username, Correct Password ---")
    for entry in valid_username_correct_password:
        print(f"Timestamp: {entry['timestamp']}, IP Address: {entry['ip_address']}, Port: {entry['port']}, Username: {entry['username']}")

    print("\n--- Valid Username, Incorrect Password ---")
    for entry in valid_username_incorrect_password:
        print(f"Timestamp: {entry['timestamp']}, IP Address: {entry['ip_address']}, Port: {entry['port']}, Username: {entry['username']}")

    print("\n--- Invalid Username ---")
    for entry in invalid_username:
        print(f"Timestamp: {entry['timestamp']}, IP Address: {entry['ip_address']}, Port: {entry['port']}, Username: {entry['username']}")


def run_logger():
    process_logs()
    upload_to_firebase()
    print_buckets()

if __name__ == "__main__":
    run_logger()
    

