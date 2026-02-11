# Security Logger
from datetime import datetime
import os

LOG_FILE = "logs/security.log"

def log_event(user, role, event, filename):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} | {user} | {role} | {event} | {filename}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# Access Pattern Monitor
from collections import defaultdict
import time
from logger import log_event

ACCESS_LIMIT = 5
TIME_WINDOW = 10  # seconds

access_records = defaultdict(list)

def monitor_access(user, role, filename):
    current_time = time.time()
    access_records[user].append(current_time)

    # Remove old timestamps
    access_records[user] = [
        t for t in access_records[user]
        if current_time - t <= TIME_WINDOW
    ]

    if len(access_records[user]) > ACCESS_LIMIT:
        log_event(user, role, "ABNORMAL_ACCESS_PATTERN", filename)
        return True

    return False

# Integrity Check
import hashlib
from logger import log_event

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def save_baseline(filepath):
    hash_value = calculate_hash(filepath)
    with open("data/baseline_hash.txt", "w") as f:
        f.write(hash_value)

def check_integrity(filepath, user, role):
    with open("data/baseline_hash.txt", "r") as f:
        baseline_hash = f.read()

    current_hash = calculate_hash(filepath)

    if baseline_hash != current_hash:
        log_event(user, role, "FILE_TAMPERING_DETECTED", filepath)
        return False

    return True

# Detector Engine
from monitor import monitor_access
from integrity_check import check_integrity

def detect(user, role, filename):
    abnormal = monitor_access(user, role, filename)
    integrity_ok = check_integrity(filename, user, role)

    if abnormal or not integrity_ok:
        return False
    return True

# Main
from detector import detect

FILE = "data/confidential_data.txt"

def read_file(user, role):
    with open(FILE, "r") as f:
        f.read()

    detect(user, role, FILE)

if __name__ == "__main__":
    print("System running normally...")
    read_file("employee_01", "staff")

import time

# Insider Attack Simulation
from detector import detect

FILE = "data/confidential_data.txt"

for i in range(7):
    with open(FILE, "r") as f:
        f.read()

    detect("insider_01", "employee", FILE)
    time.sleep(1)

# Malware Attack Simulation
from detector import detect

FILE = "data/confidential_data.txt"

for _ in range(20):
    with open(FILE, "r") as f:
        f.read()

    detect("malware_sim", "process", FILE)

# Tamper Attack Simulation
from detector import detect

FILE = "data/confidential_data.txt"

with open(FILE, "a") as f:
    f.write("\nSTOLEN DATA MODIFIED")

detect("attacker", "unknown", FILE)

# Data Exfiltration Simulation
EMPLOYEE SALARY DATA
CEO: $250,000
Manager: $120,000
Staff: $75,000

# First Time Setup
from integrity_check import save_baseline

save_baseline("data/confidential_data.txt")

