import psutil
import time
from datetime import datetime
import socket
import uuid
import winreg
from scapy.all import sniff, IP, DNS, UDP
import ipinfo
from threading import Thread, Lock
from queue import Queue
import platform
import logging
import win32evtlog
import win32con
import win32security
import win32api
import ctypes
import sys
import requests
from PIL import ImageGrab
import os
import virustotal_python
import sqlite3
import json
import traceback
from collections import Counter
import hashlib

# Setup detailed logging
logging.basicConfig(
    filename="agent.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)
logger = logging.getLogger()

# Check and elevate to admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False

if not is_admin():
    logger.info("Elevating to Administrator privileges...")
    print("Elevating to Administrator privileges...")
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to elevate privileges: {e}")
        print("Failed to elevate privileges. Please run manually as Administrator.")
        sys.exit(1)

# Ensure Windows-only
if platform.system() != "Windows":
    logger.error("This agent is designed for Windows only.")
    print("This agent is designed for Windows only.")
    sys.exit(1)

# SQLite database configuration
LOCAL_DB_FILE = "local_storage.db"
SERVER_DB_FILE = "server_local_storage.db"
db_lock = Lock()

# API endpoints
API_SERVER_URL = "http://localhost:5000"  # API server running on port 5000
VT_API_KEY_URL = f"{API_SERVER_URL}/get_vt_api_key"
COMMAND_URL = f"{API_SERVER_URL}/command"

# SQLite database setup
def init_local_db():
    """Initialize local SQLite database for agent data"""
    try:
        conn = sqlite3.connect(LOCAL_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                           agent_id TEXT, 
                           timestamp TEXT, 
                           data TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS alerts
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                           agent_id TEXT, 
                           timestamp TEXT, 
                           type TEXT,
                           severity TEXT,
                           details TEXT,
                           data TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS device_info
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                           agent_id TEXT UNIQUE, 
                           hostname TEXT,
                           os TEXT,
                           first_seen TEXT,
                           last_updated TEXT,
                           data TEXT)''')
        conn.commit()
        conn.close()
        logger.info("Local SQLite database initialized")
    except Exception as e:
        logger.error(f"Error initializing local SQLite DB: {e}\n{traceback.format_exc()}")

init_local_db()

# Fetch VirusTotal API key
def fetch_vt_api_key():
    try:
        response = requests.get(VT_API_KEY_URL, timeout=5)
        if response.status_code == 200:
            api_key = response.json().get("api_key")
            logger.info("VirusTotal API key fetched successfully")
            return api_key
        logger.warning(f"Failed to fetch VT API key: {response.status_code}")
    except Exception as e:
        logger.error(f"Error fetching VT API key: {e}\n{traceback.format_exc()}")
    return None

VT_API_KEY = fetch_vt_api_key()
vt_client = virustotal_python.Virustotal(VT_API_KEY) if VT_API_KEY else None

# ipinfo.io setup
IPINFO_TOKEN = "2a9abeea1106f8"
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

# Queues and locks
dns_queue = Queue()
network_queue = Queue()
log_queue = Queue()
alert_queue = Queue()
registry_changes = []
registry_lock = Lock()

# Hostname and persistent AGENT_ID
HOSTNAME = socket.gethostname()

def get_machine_guid():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid
    except Exception as e:
        logger.error(f"Error retrieving MachineGuid: {e}\n{traceback.format_exc()}")
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, HOSTNAME))

AGENT_ID = get_machine_guid()

# Real-time monitoring threads
stop_threads = False

def collect_system_metrics实时():
    while not stop_threads:
        try:
            metrics = {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage("C:\\").percent,
                "timestamp": datetime.now().isoformat(),
                "agent_id": AGENT_ID,
                "hostname": HOSTNAME
            }
            log_queue.put(("system_metrics", metrics))
            logger.info("System metrics collected")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def get_system_logs实时():
    while not stop_threads:
        try:
            hand = win32evtlog.OpenEventLog(None, "System")
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            system_logs = []
            for event in events[:10]:
                if event.EventID == 4663:
                    system_logs.append({
                        "event_id": event.EventID,
                        "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "desc": event.StringInserts[0] if event.StringInserts else "File deletion detected"
                    })
            if system_logs:
                log_queue.put(("system_logs", system_logs))
            win32evtlog.CloseEventLog(hand)
            logger.info("System logs collected")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting system logs: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def get_security_logs实时():
    failed_login_count = Counter()
    while not stop_threads:
        try:
            hProcess = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, win32api.GetCurrentProcessId())
            hToken = win32security.OpenProcessToken(hProcess, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            priv_id = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
            win32security.AdjustTokenPrivileges(hToken, False, [(priv_id, win32con.SE_PRIVILEGE_ENABLED)])

            hand = win32evtlog.OpenEventLog(None, "Security")
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            security_logs = []
            for event in events[:10]:
                if event.EventID in [4624, 4625, 4672, 4663]:
                    desc = event.StringInserts[0] if event.StringInserts else f"Event {event.EventID}"
                    security_logs.append({
                        "event_id": event.EventID,
                        "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "desc": desc
                    })
                    if event.EventID == 4625:
                        user = event.StringInserts[5] if len(event.StringInserts) > 5 else "Unknown"
                        failed_login_count[user] += 1
            if security_logs:
                log_queue.put(("security_logs", security_logs))
            win32evtlog.CloseEventLog(hand)
            logger.info("Security logs collected")
            
            for user, count in failed_login_count.items():
                if count > 5:
                    alert_queue.put({"type": "Multiple Failed Logins", "severity": "High", "details": f"{count} failed logins by {user}", "timestamp": datetime.now().isoformat()})
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting security logs: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def monitor_processes_with_vt实时():
    scanned_hashes = set()
    while not stop_threads:
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe']):
                proc_info = {
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "username": proc.info['username'],
                    "cpu_percent": proc.info['cpu_percent'],
                    "memory_percent": proc.info['memory_percent'],
                    "exe_path": proc.info['exe'],
                    "timestamp": datetime.now().isoformat()
                }
                processes.append(proc_info)
                
                if proc_info["exe_path"] and proc_info["exe_path"] not in scanned_hashes and vt_client:
                    try:
                        with open(proc_info["exe_path"], "rb") as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        scanned_hashes.add(proc_info["exe_path"])
                        resp = vt_client.request(f"files/{file_hash}")
                        positives = resp.data["attributes"]["last_analysis_stats"]["malicious"]
                        if positives > 0:
                            alert_queue.put({
                                "type": "Malware Detected",
                                "severity": "High",
                                "details": f"{proc_info['name']} (PID: {proc_info['pid']}) detected as malware by {positives} engines",
                                "timestamp": datetime.now().isoformat()
                            })
                    except Exception as e:
                        logger.error(f"Error scanning {proc_info['exe_path']} with VirusTotal: {e}\n{traceback.format_exc()}")
            
            log_queue.put(("processes", processes))
            logger.info("Processes monitored with VirusTotal")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def monitor_registry实时():
    global registry_changes
    while not stop_threads:
        try:
            with registry_lock:
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                value_count, _, last_modified = winreg.QueryInfoKey(key)
                change = {"key": key_path, "value_count": value_count, "last_modified": str(last_modified)}
                if change not in registry_changes:
                    registry_changes.append(change)
                    logger.info(f"Registry change detected: {key_path}")
                    log_queue.put(("registry_changes", registry_changes[-5:]))
                winreg.CloseKey(key)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error monitoring registry: {e}\n{traceback.format_exc()}")
            time.sleep(1)

def capture_traffic实时():
    def packet_handler(packet):
        try:
            if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53:
                dns_query = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
                dns_ip = packet[IP].dst
                dns_queue.put({"query": dns_query, "ip": dns_ip, "timestamp": datetime.now().isoformat()})

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if src_ip.startswith(("192.168", "10.", "172.")) or src_ip == "127.0.0.1":
                    network_queue.put(("outbound", dst_ip))
                else:
                    network_queue.put(("inbound", src_ip))
        except Exception as e:
            logger.error(f"Packet handling error: {e}\n{traceback.format_exc()}")

    try:
        sniff(prn=packet_handler, store=0)
        logger.info("Traffic capture started")
    except Exception as e:
        logger.error(f"Traffic sniffing error: {e}\n{traceback.format_exc()}")

def process_dns_data():
    dns_data = []
    while not dns_queue.empty():
        dns_entry = dns_queue.get()
        if dns_entry not in dns_data:
            dns_data.append(dns_entry)
    return dns_data

def process_network_data():
    network_data = {"inbound": [], "outbound": []}
    while not network_queue.empty():
        direction, ip = network_queue.get()
        if ip not in [entry["ip"] for entry in network_data[direction]]:
            location = get_ip_location(ip)
            network_data[direction].append({"ip": ip, **location})
    return network_data

def get_ip_location(ip):
    try:
        details = ipinfo_handler.getDetails(ip)
        return {
            "city": details.city if hasattr(details, "city") else "Unknown",
            "region": details.region if hasattr(details, "region") else "Unknown",
            "country": details.country if hasattr(details, "country") else "Unknown",
            "asn": details.org if hasattr(details, "org") else "Unknown"
        }
    except Exception as e:
        logger.error(f"ipinfo error for {ip}: {e}\n{traceback.format_exc()}")
        return {"error": str(e)}

def take_screenshot():
    try:
        screenshot = ImageGrab.grab()
        filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        screenshot.save(filename)
        logger.info(f"Screenshot saved: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error taking screenshot: {e}\n{traceback.format_exc()}")
        return None

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        logger.info(f"Process {pid} terminated")
        return True
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}\n{traceback.format_exc()}")
        return False

def handle_api_command():
    while not stop_threads:
        try:
            response = requests.get(COMMAND_URL, timeout=5)
            if response.status_code == 200:
                command = response.json()
                if command.get("action") == "screenshot":
                    filename = take_screenshot()
                    requests.post(COMMAND_URL + "/result", json={"agent_id": AGENT_ID, "result": filename})
                elif command.get("action") == "kill_process" and "pid" in command:
                    success = kill_process(command["pid"])
                    requests.post(COMMAND_URL + "/result", json={"agent_id": AGENT_ID, "result": success})
                elif command.get("action") == "list_processes":
                    processes = log_queue.queue[-1][1] if log_queue.queue else []
                    requests.post(COMMAND_URL + "/result", json={"agent_id": AGENT_ID, "result": processes})
                logger.info(f"API command handled: {command.get('action')}")
            else:
                logger.warning(f"API command fetch failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Error handling API command: {e}\n{traceback.format_exc()}")
        time.sleep(5)

def detect_anomalies(metrics, dns_data, network_data, system_logs, security_logs, processes):
    alerts = []
    try:
        if metrics and metrics.get("cpu_percent", 0) > 90:
            alerts.append({"type": "High CPU", "severity": "High", "details": f"CPU at {metrics['cpu_percent']}%", "timestamp": datetime.now().isoformat()})
        
        if len(dns_data) > 50:
            alerts.append({"type": "Frequent DNS", "severity": "Medium", "details": f"{len(dns_data)} queries detected", "timestamp": datetime.now().isoformat()})
        
        for ip_data in network_data.get("outbound", []):
            if ip_data.get("country") == "Unknown":
                alerts.append({"type": "Unknown IP", "severity": "Medium", "details": f"Outbound to {ip_data['ip']}", "timestamp": datetime.now().isoformat()})
        
        for log in system_logs:
            if log["event_id"] == 4663:
                alerts.append({"type": "File Deletion", "severity": "High", "details": log["desc"], "timestamp": datetime.now().isoformat()})
        
        for log in security_logs:
            if log["event_id"] == 4624:
                hour = int(log["time"].split(" ")[1].split(":")[0])
                if 0 <= hour <= 6:
                    alerts.append({"type": "Unusual Login Time", "severity": "Medium", "details": f"Login at {log['time']}", "timestamp": datetime.now().isoformat()})
                else:
                    alerts.append({"type": "User Login", "severity": "Low", "details": log["desc"], "timestamp": datetime.now().isoformat()})
            elif log["event_id"] == 4625:
                alerts.append({"type": "Failed Login", "severity": "Medium", "details": log["desc"], "timestamp": datetime.now().isoformat()})
            elif log["event_id"] == 4672:
                alerts.append({"type": "Privilege Change", "severity": "Medium", "details": log["desc"], "timestamp": datetime.now().isoformat()})
        
        for proc in processes:
            if proc["cpu_percent"] > 50 or "cmd.exe" in proc["name"].lower():
                alerts.append({"type": "Suspicious Process", "severity": "Medium", "details": f"{proc['name']} (PID: {proc['pid']}) by {proc['username']}", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        logger.error(f"Error in anomaly detection: {e}\n{traceback.format_exc()}")
    return alerts

def store_locally(data, table):
    """Store data in local SQLite database"""
    try:
        with db_lock:
            conn = sqlite3.connect(LOCAL_DB_FILE)
            cursor = conn.cursor()
            
            if table == "logs":
                cursor.execute(
                    "INSERT INTO logs (agent_id, timestamp, data) VALUES (?, ?, ?)",
                    (data.get("agent_id"), data.get("timestamp"), json.dumps(data))
                )
            elif table == "alerts":
                for alert in data if isinstance(data, list) else [data]:
                    cursor.execute(
                        "INSERT INTO alerts (agent_id, timestamp, type, severity, details, data) VALUES (?, ?, ?, ?, ?, ?)",
                        (alert.get("agent_id"), alert.get("timestamp"), alert.get("type"), 
                         alert.get("severity"), alert.get("details"), json.dumps(alert))
                    )
            elif table == "device_info":
                cursor.execute(
                    "INSERT OR REPLACE INTO device_info (agent_id, hostname, os, first_seen, last_updated, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (data.get("agent_id"), data.get("hostname"), data.get("os"),
                     data.get("first_seen"), data.get("last_updated"), json.dumps(data))
                )
            
            conn.commit()
            conn.close()
            logger.info(f"Data stored locally in {table}")
    except Exception as e:
        logger.error(f"Error storing data locally in {table}: {e}\n{traceback.format_exc()}")

def sync_to_server():
    """Sync local data to server via HTTP API"""
    try:
        with db_lock:
            conn = sqlite3.connect(LOCAL_DB_FILE)
            cursor = conn.cursor()
            
            # Sync logs
            cursor.execute("SELECT id, agent_id, timestamp, data FROM logs")
            logs = cursor.fetchall()
            if logs:
                for log_id, agent_id, timestamp, data in logs:
                    try:
                        response = requests.post(
                            f"{API_SERVER_URL}/api/v1/ingest/log",
                            json=json.loads(data),
                            timeout=5
                        )
                        if response.status_code == 200:
                            cursor.execute("DELETE FROM logs WHERE id = ?", (log_id,))
                    except Exception as e:
                        logger.error(f"Failed to sync log {log_id}: {e}")
                        break
                conn.commit()
                logger.info(f"Synced {len(logs)} logs to server")
            
            # Sync alerts
            cursor.execute("SELECT id, agent_id, timestamp, type, severity, details, data FROM alerts")
            alerts = cursor.fetchall()
            if alerts:
                for alert_id, agent_id, timestamp, alert_type, severity, details, data in alerts:
                    try:
                        response = requests.post(
                            f"{API_SERVER_URL}/api/v1/ingest/alert",
                            json=json.loads(data),
                            timeout=5
                        )
                        if response.status_code == 200:
                            cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
                    except Exception as e:
                        logger.error(f"Failed to sync alert {alert_id}: {e}")
                        break
                conn.commit()
                logger.info(f"Synced {len(alerts)} alerts to server")
            
            # Sync device info
            cursor.execute("SELECT agent_id, hostname, os, first_seen, last_updated, data FROM device_info")
            devices = cursor.fetchall()
            if devices:
                for agent_id, hostname, os_info, first_seen, last_updated, data in devices:
                    try:
                        response = requests.post(
                            f"{API_SERVER_URL}/api/v1/ingest/device",
                            json=json.loads(data),
                            timeout=5
                        )
                        if response.status_code == 200:
                            logger.info(f"Synced device info for {agent_id}")
                    except Exception as e:
                        logger.error(f"Failed to sync device {agent_id}: {e}")
            
            conn.close()
            
    except Exception as e:
        logger.error(f"Error syncing to server: {e}\n{traceback.format_exc()}")

def check_server_connectivity():
    """Check if server API is accessible"""
    try:
        response = requests.get(f"{API_SERVER_URL}/api/v1/dashboard", timeout=2)
        return response.status_code == 200
    except Exception:
        return False

def store_data实时():
    """Store collected data to database"""
    log_data = {
        "agent_id": AGENT_ID,
        "timestamp": datetime.now().isoformat(),
        "system_metrics": {},
        "dns_queries": [],
        "network": {"inbound": [], "outbound": []},
        "system_logs": [],
        "security_logs": [],
        "processes": [],
        "registry_changes": []
    }
    
    while not stop_threads:
        try:
            while not log_queue.empty():
                key, value = log_queue.get()
                log_data[key] = value
            
            dns_data = process_dns_data()
            network_data = process_network_data()
            if dns_data:
                log_data["dns_queries"] = dns_data
            if network_data["inbound"] or network_data["outbound"]:
                log_data["network"] = network_data
            
            alerts = []
            while not alert_queue.empty():
                alerts.append(alert_queue.get())
            
            detected_alerts = detect_anomalies(
                log_data["system_metrics"],
                log_data["dns_queries"],
                log_data["network"],
                log_data["system_logs"],
                log_data["security_logs"],
                log_data["processes"]
            )
            alerts.extend(detected_alerts)
            
            # Add agent_id to all alerts
            for alert in alerts:
                alert["agent_id"] = AGENT_ID
            
            # Store data locally first
            store_locally(log_data.copy(), "logs")
            if alerts:
                store_locally(alerts, "alerts")
            
            # Try to sync to server
            if check_server_connectivity():
                sync_to_server()
                logger.info(f"Data synced to server for agent {AGENT_ID}")
                print(f"Data synced to server for agent {AGENT_ID}")
            else:
                logger.warning("Server database not accessible. Data stored locally.")
                print("Server database not accessible. Data stored locally.")
                
        except Exception as e:
            logger.error(f"Error in store_data: {e}\n{traceback.format_exc()}")
            store_locally(log_data, "logs")
            if alerts:
                store_locally(alerts, "alerts")
        
        time.sleep(5)

def store_device_info():
    """Store device information"""
    try:
        device_data = {
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "os": f"{platform.system()} {platform.release()}",
            "first_seen": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }
        store_locally(device_data, "device_info")
        logger.info(f"Device info stored for {AGENT_ID}")
        
        # Try to sync immediately
        if check_server_connectivity():
            sync_to_server()
    except Exception as e:
        logger.error(f"Error storing device info: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    store_device_info()

    threads = [
        Thread(target=collect_system_metrics实时),
        Thread(target=get_system_logs实时),
        Thread(target=get_security_logs实时),
        Thread(target=monitor_processes_with_vt实时),
        Thread(target=monitor_registry实时),
        Thread(target=capture_traffic实时),
        Thread(target=handle_api_command),
        Thread(target=store_data实时)
    ]

    for t in threads:
        t.daemon = True
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        print("Agent stopped by user")
        stop_threads = True
        for t in threads:
            t.join(timeout=5)