
#!/usr/bin/env python3
# System Insight Terminal Backend
# This is a simple Flask API that provides system information

import os
import sys
import json
import socket
import platform
import subprocess
import psutil
import datetime
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import netifaces
import cryptography
from cryptography.fernet import Fernet
import hashlib
import time

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('logs/app.log', maxBytes=10485760, backupCount=5),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("SystemInsightTerminal")

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Generate a secret key for this session
SECRET_KEY = Fernet.generate_key()
cipher_suite = Fernet(SECRET_KEY)

# Define security policies
SECURITY_POLICIES = {
    "password_policy": {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special_chars": True,
        "max_age_days": 90,
        "prevent_reuse": True,
        "lockout_threshold": 5
    },
    "firewall_rules": {
        "default_incoming": "deny",
        "default_outgoing": "allow",
        "allowed_services": ["ssh", "http", "https", "dns"],
        "blocked_countries": ["XX", "YY", "ZZ"]
    },
    "access_control": {
        "enforce_2fa": True,
        "session_timeout_minutes": 30,
        "ip_whitelist_enabled": True,
        "privileged_access_review": "weekly"
    },
    "data_protection": {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "data_classification_enforced": True,
        "data_retention_period_days": 365
    },
    "audit_logging": {
        "log_retention_days": 90,
        "sensitive_action_logging": True,
        "log_review_frequency": "daily",
        "alert_on_suspicious": True
    }
}

# Hash function for secure operations
def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Error handler
@app.errorhandler(Exception)
def handle_error(e):
    logger.error(f"Error: {str(e)}")
    return jsonify({"status": "error", "message": str(e)}), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "timestamp": datetime.datetime.now().isoformat()})

# System information endpoint
@app.route('/api/system/info', methods=['GET'])
def system_info():
    # Log the request
    logger.info(f"System info requested from {request.remote_addr}")
    
    # Get system information
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "architecture": platform.architecture(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
    }
    
    return jsonify(info)

# CPU information endpoint
@app.route('/api/system/cpu', methods=['GET'])
def cpu_info():
    # Get CPU information
    cpu_info = {
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "cpu_frequency": {
            "current": psutil.cpu_freq().current if psutil.cpu_freq() else None,
            "min": psutil.cpu_freq().min if psutil.cpu_freq() else None,
            "max": psutil.cpu_freq().max if psutil.cpu_freq() else None
        },
        "cpu_usage_per_core": [percentage for percentage in psutil.cpu_percent(percpu=True)],
        "total_cpu_usage": psutil.cpu_percent()
    }
    
    return jsonify(cpu_info)

# Memory information endpoint
@app.route('/api/system/memory', methods=['GET'])
def memory_info():
    # Get memory information
    virtual_memory = psutil.virtual_memory()
    swap_memory = psutil.swap_memory()
    
    memory_info = {
        "virtual_memory": {
            "total": virtual_memory.total,
            "available": virtual_memory.available,
            "used": virtual_memory.used,
            "percentage": virtual_memory.percent
        },
        "swap_memory": {
            "total": swap_memory.total,
            "used": swap_memory.used,
            "free": swap_memory.free,
            "percentage": swap_memory.percent
        }
    }
    
    return jsonify(memory_info)

# Disk information endpoint
@app.route('/api/system/disk', methods=['GET'])
def disk_info():
    # Get disk information
    partitions = []
    for partition in psutil.disk_partitions():
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            partitions.append({
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "filesystem_type": partition.fstype,
                "total_size": partition_usage.total,
                "used": partition_usage.used,
                "free": partition_usage.free,
                "percentage": partition_usage.percent
            })
        except PermissionError:
            # Some partitions may not be accessible
            continue
    
    io_counters = psutil.disk_io_counters()
    disk_io = {
        "read_count": io_counters.read_count if io_counters else None,
        "write_count": io_counters.write_count if io_counters else None,
        "read_bytes": io_counters.read_bytes if io_counters else None,
        "write_bytes": io_counters.write_bytes if io_counters else None
    }
    
    disk_info = {
        "partitions": partitions,
        "io_counters": disk_io
    }
    
    return jsonify(disk_info)

# Network information endpoint
@app.route('/api/system/network', methods=['GET'])
def network_info():
    # Get network interfaces
    interfaces = {}
    for interface in netifaces.interfaces():
        try:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                interfaces[interface] = {
                    "ip": addresses[netifaces.AF_INET][0]['addr'],
                    "netmask": addresses[netifaces.AF_INET][0]['netmask'],
                    "mac": addresses[netifaces.AF_LINK][0]['addr'] if netifaces.AF_LINK in addresses else None
                }
        except Exception as e:
            logger.error(f"Error getting network info for {interface}: {str(e)}")
    
    # Get network statistics
    io_counters = psutil.net_io_counters()
    network_io = {
        "bytes_sent": io_counters.bytes_sent,
        "bytes_received": io_counters.bytes_recv,
        "packets_sent": io_counters.packets_sent,
        "packets_received": io_counters.packets_recv
    }
    
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connections.append({
            "fd": conn.fd,
            "family": conn.family,
            "type": conn.type,
            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            "status": conn.status,
            "pid": conn.pid
        })
    
    network_info = {
        "interfaces": interfaces,
        "io_counters": network_io,
        "connections": connections
    }
    
    return jsonify(network_info)

# Process information endpoint
@app.route('/api/system/processes', methods=['GET'])
def process_info():
    # Get process information
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            pinfo = proc.info
            pinfo['create_time'] = datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat()
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return jsonify(processes)

# Security audit endpoint
@app.route('/api/security/audit', methods=['GET'])
def security_audit():
    # Perform a basic security audit
    issues = []
    
    # Check for SSH
    try:
        ssh_config = subprocess.check_output("find /etc/ssh -name 'sshd_config' -type f", shell=True).decode().strip()
        if ssh_config:
            # Check for root login
            root_login = subprocess.check_output(f"grep -i 'PermitRootLogin' {ssh_config}", shell=True).decode().strip()
            if 'yes' in root_login.lower():
                issues.append({
                    "severity": "high",
                    "category": "ssh",
                    "issue": "Root login is permitted",
                    "recommendation": "Disable root login in SSH configuration"
                })
    except:
        # SSH might not be installed
        pass
    
    # Check for open ports
    try:
        open_ports = subprocess.check_output("netstat -tuln | grep LISTEN", shell=True).decode().strip()
        if '0.0.0.0:23' in open_ports:
            issues.append({
                "severity": "high",
                "category": "network",
                "issue": "Telnet port (23) is open",
                "recommendation": "Disable telnet and use SSH instead"
            })
    except:
        pass
    
    # Check for updates
    try:
        if platform.system() == 'Linux':
            if os.path.exists('/etc/debian_version'):
                updates = subprocess.check_output("apt list --upgradable 2>/dev/null | grep -i security", shell=True).decode().strip()
                if updates:
                    issues.append({
                        "severity": "medium",
                        "category": "updates",
                        "issue": "Security updates are available",
                        "recommendation": "Run 'apt upgrade' to install security updates"
                    })
    except:
        pass
    
    # Simulate other checks
    issues.extend([
        {
            "severity": "medium",
            "category": "filesystem",
            "issue": "Sensitive file has incorrect permissions: /etc/shadow (644)",
            "recommendation": "Run 'chmod 600 /etc/shadow' to fix permissions"
        },
        {
            "severity": "low",
            "category": "user",
            "issue": "User 'test' has an empty password",
            "recommendation": "Set a strong password for user 'test'"
        },
        {
            "severity": "high",
            "category": "software",
            "issue": "Outdated version of OpenSSL (vulnerable to CVE-2023-0286)",
            "recommendation": "Update OpenSSL to the latest version"
        }
    ])
    
    audit_result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "system": platform.system(),
        "hostname": socket.gethostname(),
        "issues_count": len(issues),
        "issues_by_severity": {
            "high": len([i for i in issues if i["severity"] == "high"]),
            "medium": len([i for i in issues if i["severity"] == "medium"]),
            "low": len([i for i in issues if i["severity"] == "low"])
        },
        "issues": issues
    }
    
    # Log the audit
    logger.info(f"Security audit completed: {audit_result['issues_count']} issues found")
    
    return jsonify(audit_result)

# Security policies endpoint
@app.route('/api/security/policies', methods=['GET'])
def security_policies():
    policy_id = request.args.get('id')
    
    if policy_id:
        if policy_id in SECURITY_POLICIES:
            return jsonify({policy_id: SECURITY_POLICIES[policy_id]})
        else:
            return jsonify({"status": "error", "message": f"Policy {policy_id} not found"}), 404
    
    return jsonify(SECURITY_POLICIES)

# Log analysis endpoint
@app.route('/api/logs/analyze', methods=['GET'])
def analyze_logs():
    # Parameters
    log_path = request.args.get('path', '/var/log/auth.log')
    service = request.args.get('service')
    level = request.args.get('level')
    limit = int(request.args.get('limit', 100))
    
    try:
        # For demonstration, we'll generate synthetic log data instead of reading actual files
        log_entries = generate_synthetic_logs(service, level, limit)
        
        # Analyze logs
        analysis = {
            "total_entries": len(log_entries),
            "levels": {
                "info": len([log for log in log_entries if log["level"] == "INFO"]),
                "warning": len([log for log in log_entries if log["level"] == "WARNING"]),
                "error": len([log for log in log_entries if log["level"] == "ERROR"]),
                "critical": len([log for log in log_entries if log["level"] == "CRITICAL"])
            },
            "services": {},
            "entries": log_entries[:limit]
        }
        
        # Count by service
        for entry in log_entries:
            service_name = entry["service"]
            if service_name not in analysis["services"]:
                analysis["services"][service_name] = 0
            analysis["services"][service_name] += 1
        
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def generate_synthetic_logs(service=None, level=None, count=100):
    logs = []
    services = ["Authentication", "Firewall", "Database", "FileSystem", "WebServer", "SSHD", "NetworkManager"]
    levels = ["INFO", "WARNING", "ERROR", "CRITICAL"]
    
    messages = {
        "Authentication": {
            "INFO": ["User login successful: {user}", "Password changed for user: {user}", "New user created: {user}"],
            "WARNING": ["Failed login attempt for user: {user}", "Multiple login attempts for user: {user}", "Password expired for user: {user}"],
            "ERROR": ["Authentication service error", "LDAP connection timeout", "Invalid authentication token"],
            "CRITICAL": ["Possible brute force attack detected", "Admin account lockout: {user}", "Authentication database corrupted"]
        },
        "Firewall": {
            "INFO": ["Rule added: {rule}", "Rule updated: {rule}", "Firewall restarted"],
            "WARNING": ["Blocked connection attempt from {ip}", "Rate limiting applied to {ip}", "Unusual traffic pattern from {ip}"],
            "ERROR": ["Firewall rule parsing error", "Failed to apply rule: {rule}", "Firewall service crash"],
            "CRITICAL": ["Firewall bypass detected", "Multiple rule violations from {ip}", "Firewall disabled"]
        },
        "Database": {
            "INFO": ["Database backup completed", "New table created: {table}", "Query optimization complete"],
            "WARNING": ["Slow query detected: {query}", "High memory usage", "Approaching storage limit"],
            "ERROR": ["Query failed: {query}", "Connection timeout after {time}s", "Deadlock detected in transaction"],
            "CRITICAL": ["Database corruption detected", "Data loss event", "Storage failure"]
        }
    }
    
    users = ["admin", "user1", "system", "guest", "operator", "root"]
    ips = ["192.168.1.100", "10.0.0.15", "172.16.254.1", "203.0.113.42", "198.51.100.23", "192.0.2.18"]
    rules = ["allow tcp port 22", "deny ip from 192.168.0.0/16 to any", "allow udp port 53", "deny icmp from any to 10.0.0.1"]
    tables = ["users", "logs", "sessions", "products", "transactions", "audit_trail"]
    queries = ["SELECT * FROM users", "UPDATE sessions SET active=0", "INSERT INTO logs VALUES (...)", "DELETE FROM cache"]
    
    # Generate random logs
    for i in range(count):
        log_service = service if service else random.choice(services)
        log_level = level if level else random.choice(levels)
        
        # Generate a timestamp within the last week
        timestamp = (datetime.datetime.now() - datetime.timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )).isoformat()
        
        # Generate message
        if log_service in messages and log_level in messages[log_service]:
            message_template = random.choice(messages[log_service][log_level])
            message = message_template.format(
                user=random.choice(users),
                ip=random.choice(ips),
                rule=random.choice(rules),
                table=random.choice(tables),
                query=random.choice(queries),
                time=random.randint(5, 60)
            )
        else:
            message = f"{log_service} {log_level.lower()} message"
        
        logs.append({
            "timestamp": timestamp,
            "level": log_level,
            "service": log_service,
            "message": message
        })
    
    # Sort by timestamp
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return logs

# Command execution endpoint (restricted to safe commands)
@app.route('/api/system/exec', methods=['POST'])
def execute_command():
    data = request.json
    
    if not data or 'command' not in data:
        return jsonify({"status": "error", "message": "No command provided"}), 400
    
    command = data['command']
    logger.info(f"Command execution requested: {command}")
    
    # List of allowed safe commands
    safe_commands = [
        'uname -a', 'uptime', 'df -h', 'free -m', 'ps aux', 'netstat -tuln',
        'ifconfig', 'ip addr', 'ping -c 4 google.com', 'date', 'whoami',
        'cat /etc/os-release', 'lsblk', 'ss -tuln'
    ]
    
    # Check if command is safe
    is_safe = False
    for safe_cmd in safe_commands:
        if command == safe_cmd or command.startswith(safe_cmd + ' '):
            is_safe = True
            break
    
    if not is_safe:
        logger.warning(f"Blocked execution of potentially unsafe command: {command}")
        return jsonify({"status": "error", "message": "Command not allowed for security reasons"}), 403
    
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
        return jsonify({"status": "success", "output": output})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": e.output.decode() if e.output else str(e)}), 500

# Run the server if executed directly
if __name__ == '__main__':
    # Print startup information
    logger.info("="*50)
    logger.info(f"Starting System Insight Terminal Backend")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Hostname: {socket.gethostname()}")
    logger.info("="*50)
    
    # Start the server
    app.run(host='0.0.0.0', port=5000, debug=True)
