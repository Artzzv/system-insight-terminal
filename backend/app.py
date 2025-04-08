
#!/usr/bin/env python3
# System Insight Terminal Backend
# This is a Flask API that provides real system information

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
import re
import glob

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
    
    # Get real system information
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
    # Get real CPU information
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
    # Get real memory information
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
    # Get real disk information
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
    # Get real network interfaces
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
    
    # Get real network statistics
    io_counters = psutil.net_io_counters()
    network_io = {
        "bytes_sent": io_counters.bytes_sent,
        "bytes_received": io_counters.bytes_recv,
        "packets_sent": io_counters.packets_sent,
        "packets_received": io_counters.packets_recv
    }
    
    # Get real network connections
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
    # Get real process information
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            pinfo = proc.info
            pinfo['create_time'] = datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat()
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return jsonify(processes)

# Security audit endpoint - Real system checks
@app.route('/api/security/audit', methods=['GET'])
def security_audit():
    # Perform real security audit
    issues = []
    
    # Check for SSH configuration if exists
    try:
        ssh_config_files = glob.glob('/etc/ssh/sshd_config*')
        for ssh_config in ssh_config_files:
            if os.path.exists(ssh_config):
                # Check for root login
                try:
                    with open(ssh_config, 'r') as f:
                        config_content = f.read()
                        if re.search(r'PermitRootLogin\s+yes', config_content, re.IGNORECASE):
                            issues.append({
                                "severity": "high",
                                "category": "ssh",
                                "issue": f"Root login is permitted in {ssh_config}",
                                "recommendation": f"Disable root login in {ssh_config}"
                            })
                except Exception as e:
                    logger.error(f"Error reading SSH config: {str(e)}")
    except Exception as e:
        logger.error(f"Error checking SSH configuration: {str(e)}")
    
    # Check for open ports
    try:
        if platform.system() == 'Linux':
            netstat_output = subprocess.check_output("netstat -tuln | grep LISTEN", shell=True).decode()
            if '0.0.0.0:23' in netstat_output or ':::23' in netstat_output:
                issues.append({
                    "severity": "high",
                    "category": "network",
                    "issue": "Telnet port (23) is open",
                    "recommendation": "Disable telnet and use SSH instead"
                })
        elif platform.system() == 'Windows':
            netstat_output = subprocess.check_output("netstat -ano | findstr LISTENING", shell=True).decode()
            telnet_match = re.search(r':23\s+.*LISTENING', netstat_output)
            if telnet_match:
                issues.append({
                    "severity": "high",
                    "category": "network",
                    "issue": "Telnet port (23) is open",
                    "recommendation": "Disable telnet and use SSH instead"
                })
    except Exception as e:
        logger.error(f"Error checking open ports: {str(e)}")
    
    # Check for security updates
    try:
        if platform.system() == 'Linux':
            if os.path.exists('/etc/debian_version'):
                try:
                    updates = subprocess.check_output("apt list --upgradable 2>/dev/null | grep -i security", shell=True).decode()
                    if updates:
                        issues.append({
                            "severity": "medium",
                            "category": "updates",
                            "issue": "Security updates are available",
                            "recommendation": "Run 'apt upgrade' to install security updates",
                            "details": updates[:1000]  # Limit the length
                        })
                except:
                    pass
            elif os.path.exists('/etc/redhat-release'):
                try:
                    updates = subprocess.check_output("yum check-update --security 2>/dev/null", shell=True).decode()
                    if not "No packages needed for security" in updates:
                        issues.append({
                            "severity": "medium",
                            "category": "updates",
                            "issue": "Security updates are available",
                            "recommendation": "Run 'yum update --security' to install security updates",
                            "details": updates[:1000]  # Limit the length
                        })
                except:
                    pass
        elif platform.system() == 'Windows':
            try:
                # PowerShell command to check for Windows updates
                updates = subprocess.check_output("powershell -Command \"Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 10 | Format-Table -AutoSize\"", shell=True).decode()
                issues.append({
                    "severity": "low",
                    "category": "updates",
                    "issue": "Windows update information",
                    "recommendation": "Check Windows Update for any pending security updates",
                    "details": updates
                })
            except:
                pass
    except Exception as e:
        logger.error(f"Error checking security updates: {str(e)}")
    
    # Check file permissions
    try:
        if platform.system() == 'Linux':
            critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            for file_path in critical_files:
                if os.path.exists(file_path):
                    file_stat = os.stat(file_path)
                    file_mode = oct(file_stat.st_mode)[-3:]
                    if file_path == '/etc/shadow' and file_mode != '600' and file_mode != '000':
                        issues.append({
                            "severity": "high",
                            "category": "filesystem",
                            "issue": f"Sensitive file has incorrect permissions: {file_path} ({file_mode})",
                            "recommendation": f"Run 'chmod 600 {file_path}' to fix permissions"
                        })
                    elif file_path != '/etc/shadow' and int(file_mode[1]) > 4:
                        issues.append({
                            "severity": "medium",
                            "category": "filesystem",
                            "issue": f"Critical file has liberal permissions: {file_path} ({file_mode})",
                            "recommendation": f"Run 'chmod 644 {file_path}' to fix permissions"
                        })
    except Exception as e:
        logger.error(f"Error checking file permissions: {str(e)}")
    
    # Audit result
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

# Read real system logs
def read_system_logs(log_path, limit=100):
    log_entries = []
    
    try:
        if os.path.exists(log_path):
            with open(log_path, 'r', errors='replace') as f:
                lines = f.readlines()[-limit:]
                for line in lines:
                    log_entries.append(parse_log_line(line, os.path.basename(log_path)))
        else:
            if platform.system() == 'Linux':
                # Try to use journalctl
                output = subprocess.check_output(f"journalctl -n {limit}", shell=True).decode()
                lines = output.splitlines()
                for line in lines:
                    log_entries.append(parse_log_line(line, "journalctl"))
            elif platform.system() == 'Windows':
                # Try to use PowerShell to fetch event logs
                output = subprocess.check_output(f"powershell -Command \"Get-EventLog -LogName System -Newest {limit} | Format-Table TimeGenerated, EntryType, Source, Message -AutoSize\"", shell=True).decode()
                lines = output.splitlines()
                for line in lines:
                    if line.strip() and not line.startswith('TimeGenerated'):
                        log_entries.append(parse_log_line(line, "Windows-System"))
    except Exception as e:
        logger.error(f"Error reading log file {log_path}: {str(e)}")
        log_entries.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "level": "ERROR",
            "service": "LogReader",
            "message": f"Failed to read log: {str(e)}"
        })
    
    return log_entries

def parse_log_line(line, source):
    line = line.strip()
    if not line:
        return None
    
    timestamp = datetime.datetime.now().isoformat()
    level = "INFO"
    service = source
    message = line
    
    # Try to extract timestamp, level, and message from common log formats
    try:
        # Look for timestamp patterns
        timestamp_match = re.search(r'\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[-+]\d{2}:?\d{2})?\b', line)
        if timestamp_match:
            timestamp = timestamp_match.group(0)
            line = line.replace(timestamp, '')
        
        # Look for log levels
        level_match = re.search(r'\b(DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY)\b', line, re.IGNORECASE)
        if level_match:
            level = level_match.group(0).upper()
            line = line.replace(level_match.group(0), '')
        
        # Look for service/source
        if '[' in line and ']' in line:
            service_match = re.search(r'\[(.*?)\]', line)
            if service_match:
                service = service_match.group(1)
                line = line.replace(service_match.group(0), '')
        
        # The rest is the message
        message = line.strip()
    except:
        pass  # If parsing fails, just use the defaults
    
    return {
        "timestamp": timestamp,
        "level": level,
        "service": service,
        "message": message
    }

# Log analysis endpoint
@app.route('/api/logs/analyze', methods=['GET'])
def analyze_logs():
    # Parameters
    log_path = request.args.get('path', '/var/log/syslog' if platform.system() == 'Linux' else 'System')
    service = request.args.get('service')
    level = request.args.get('level')
    limit = int(request.args.get('limit', 100))
    
    try:
        # Read real logs based on OS
        if platform.system() == 'Linux':
            if log_path == 'System':
                log_path = '/var/log/syslog'
            elif log_path == 'Auth':
                log_path = '/var/log/auth.log'
            elif log_path == 'Kernel':
                log_path = '/var/log/kern.log'
            
            log_entries = read_system_logs(log_path, limit)
        
        elif platform.system() == 'Windows':
            if log_path == 'System':
                output = subprocess.check_output(f"powershell -Command \"Get-EventLog -LogName System -Newest {limit} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json\"", shell=True).decode()
                windows_logs = json.loads(output)
                log_entries = []
                
                # Convert Windows event logs to our format
                for entry in windows_logs:
                    log_entries.append({
                        "timestamp": entry["TimeGenerated"],
                        "level": entry["EntryType"],
                        "service": entry["Source"],
                        "message": entry["Message"]
                    })
            
            elif log_path == 'Security':
                # Accessing security logs may require admin privileges
                try:
                    output = subprocess.check_output(f"powershell -Command \"Get-EventLog -LogName Security -Newest {limit} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json\"", shell=True).decode()
                    windows_logs = json.loads(output)
                    log_entries = []
                    
                    for entry in windows_logs:
                        log_entries.append({
                            "timestamp": entry["TimeGenerated"],
                            "level": entry["EntryType"],
                            "service": entry["Source"],
                            "message": entry["Message"]
                        })
                except:
                    log_entries = [{
                        "timestamp": datetime.datetime.now().isoformat(),
                        "level": "ERROR",
                        "service": "LogReader",
                        "message": "Failed to read security logs. Administrative privileges required."
                    }]
            
            elif log_path == 'Application':
                output = subprocess.check_output(f"powershell -Command \"Get-EventLog -LogName Application -Newest {limit} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json\"", shell=True).decode()
                windows_logs = json.loads(output)
                log_entries = []
                
                for entry in windows_logs:
                    log_entries.append({
                        "timestamp": entry["TimeGenerated"],
                        "level": entry["EntryType"],
                        "service": entry["Source"],
                        "message": entry["Message"]
                    })
            else:
                log_entries = read_system_logs(log_path, limit)
        else:
            # Other OS - just try to read the file
            log_entries = read_system_logs(log_path, limit)
        
        # Filter by service if specified
        if service:
            log_entries = [log for log in log_entries if log and service.lower() in log["service"].lower()]
        
        # Filter by level if specified
        if level:
            log_entries = [log for log in log_entries if log and level.upper() == log["level"].upper()]
        
        # Analyze logs for patterns and anomalies (simple analysis)
        error_count = len([log for log in log_entries if log and "ERROR" in log["level"].upper()])
        warning_count = len([log for log in log_entries if log and "WARNING" in log["level"].upper()])
        service_counts = {}
        
        for entry in log_entries:
            if entry:
                service_name = entry["service"]
                if service_name not in service_counts:
                    service_counts[service_name] = 0
                service_counts[service_name] += 1
        
        # Most frequent patterns - very basic implementation
        patterns = {}
        for entry in log_entries:
            if entry and entry["message"]:
                words = re.findall(r'\b\w+\b', entry["message"].lower())
                for word in words:
                    if len(word) > 4:  # Only consider words longer than 4 chars
                        if word not in patterns:
                            patterns[word] = 0
                        patterns[word] += 1
        
        # Get top 10 patterns
        top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Basic time series for visualization
        timestamps = {}
        for entry in log_entries:
            if entry and entry["timestamp"]:
                try:
                    # Try to parse the timestamp
                    dt = datetime.datetime.fromisoformat(entry["timestamp"].replace('Z', '+00:00'))
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    if hour_key not in timestamps:
                        timestamps[hour_key] = 0
                    timestamps[hour_key] += 1
                except:
                    pass
        
        time_series = [{"time": k, "count": v} for k, v in timestamps.items()]
        time_series.sort(key=lambda x: x["time"])
        
        analysis = {
            "total_entries": len([log for log in log_entries if log]),
            "levels": {
                "info": len([log for log in log_entries if log and "INFO" in log["level"].upper()]),
                "warning": warning_count,
                "error": error_count,
                "critical": len([log for log in log_entries if log and "CRITICAL" in log["level"].upper()]),
            },
            "services": service_counts,
            "entries": [log for log in log_entries if log][:limit],
            "patterns": top_patterns,
            "time_series": time_series,
            "anomalies": [] # Advanced anomaly detection would go here
        }
        
        # If there's a high error rate, flag it as an anomaly
        if error_count > 0 and len(log_entries) > 0:
            error_rate = error_count / len([log for log in log_entries if log])
            if error_rate > 0.2:  # More than 20% errors
                analysis["anomalies"].append({
                    "type": "high_error_rate",
                    "description": f"High error rate detected: {error_rate:.2%}",
                    "severity": "high"
                })
        
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Security policies endpoint - Read from OS
@app.route('/api/security/policies', methods=['GET'])
def security_policies():
    policies = {}
    
    # Password policy
    try:
        if platform.system() == 'Linux':
            # Try to read password policy from /etc/login.defs and PAM
            password_policy = {
                "min_length": None,
                "require_uppercase": False,
                "require_lowercase": False,
                "require_numbers": False,
                "require_special_chars": False,
                "max_age_days": None,
                "prevent_reuse": False,
                "lockout_threshold": None
            }
            
            # Check /etc/login.defs
            if os.path.exists('/etc/login.defs'):
                with open('/etc/login.defs', 'r') as f:
                    login_defs = f.read()
                    pass_max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', login_defs)
                    if pass_max_days:
                        password_policy["max_age_days"] = int(pass_max_days.group(1))
            
            # Check PAM config
            if os.path.exists('/etc/pam.d/common-password'):
                with open('/etc/pam.d/common-password', 'r') as f:
                    pam_config = f.read()
                    min_length = re.search(r'minlen=(\d+)', pam_config)
                    if min_length:
                        password_policy["min_length"] = int(min_length.group(1))
                    
                    ucredit = re.search(r'ucredit=(-?\d+)', pam_config)
                    if ucredit and int(ucredit.group(1)) < 0:
                        password_policy["require_uppercase"] = True
                    
                    lcredit = re.search(r'lcredit=(-?\d+)', pam_config)
                    if lcredit and int(lcredit.group(1)) < 0:
                        password_policy["require_lowercase"] = True
                    
                    dcredit = re.search(r'dcredit=(-?\d+)', pam_config)
                    if dcredit and int(dcredit.group(1)) < 0:
                        password_policy["require_numbers"] = True
                    
                    ocredit = re.search(r'ocredit=(-?\d+)', pam_config)
                    if ocredit and int(ocredit.group(1)) < 0:
                        password_policy["require_special_chars"] = True
            
            # Check account lockout settings
            if os.path.exists('/etc/pam.d/common-auth'):
                with open('/etc/pam.d/common-auth', 'r') as f:
                    auth_config = f.read()
                    deny = re.search(r'deny=(\d+)', auth_config)
                    if deny:
                        password_policy["lockout_threshold"] = int(deny.group(1))
            
            policies["password_policy"] = password_policy
            
        elif platform.system() == 'Windows':
            # Use PowerShell to get password policy information
            try:
                output = subprocess.check_output("powershell -Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network' | Select-Object -Property *\"", shell=True).decode()
                
                # Try another approach with secpol.msc
                output = subprocess.check_output("powershell -Command \"echo Y | secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg && type C:\\Windows\\Temp\\secpol.cfg\"", shell=True).decode()
                
                password_policy = {
                    "min_length": None,
                    "require_uppercase": None,
                    "require_lowercase": None,
                    "require_numbers": None,
                    "require_special_chars": None,
                    "max_age_days": None,
                    "prevent_reuse": None,
                    "lockout_threshold": None
                }
                
                # Parse the output
                min_length = re.search(r'MinimumPasswordLength\s*=\s*(\d+)', output)
                if min_length:
                    password_policy["min_length"] = int(min_length.group(1))
                
                complexity = re.search(r'PasswordComplexity\s*=\s*(\d+)', output)
                if complexity and complexity.group(1) == '1':
                    password_policy["require_uppercase"] = True
                    password_policy["require_lowercase"] = True
                    password_policy["require_numbers"] = True
                    password_policy["require_special_chars"] = True
                
                max_age = re.search(r'MaximumPasswordAge\s*=\s*(\d+)', output)
                if max_age:
                    password_policy["max_age_days"] = int(max_age.group(1))
                
                password_history = re.search(r'PasswordHistorySize\s*=\s*(\d+)', output)
                if password_history and int(password_history.group(1)) > 0:
                    password_policy["prevent_reuse"] = True
                
                lockout = re.search(r'LockoutBadCount\s*=\s*(\d+)', output)
                if lockout:
                    password_policy["lockout_threshold"] = int(lockout.group(1))
                
                policies["password_policy"] = password_policy
            except Exception as e:
                logger.error(f"Error getting Windows password policy: {str(e)}")
                # Fallback to default policy
                policies["password_policy"] = {
                    "min_length": None,
                    "require_uppercase": None,
                    "require_lowercase": None,
                    "require_numbers": None,
                    "require_special_chars": None,
                    "max_age_days": None,
                    "prevent_reuse": None,
                    "lockout_threshold": None
                }
    except Exception as e:
        logger.error(f"Error reading password policy: {str(e)}")
    
    # Firewall rules
    try:
        firewall_rules = {
            "default_incoming": None,
            "default_outgoing": None,
            "allowed_services": [],
            "blocked_countries": []
        }
        
        if platform.system() == 'Linux':
            try:
                # Check iptables
                iptables_output = subprocess.check_output("iptables -L", shell=True).decode()
                
                # Check default policies
                input_policy = re.search(r'Chain INPUT \(policy ([A-Z]+)\)', iptables_output)
                if input_policy:
                    firewall_rules["default_incoming"] = input_policy.group(1).lower()
                
                output_policy = re.search(r'Chain OUTPUT \(policy ([A-Z]+)\)', iptables_output)
                if output_policy:
                    firewall_rules["default_outgoing"] = output_policy.group(1).lower()
                
                # Check for allowed services
                for service in ["ssh", "http", "https", "dns"]:
                    if re.search(rf'(tcp|udp).*dpt:{service}', iptables_output, re.IGNORECASE) or re.search(rf'(tcp|udp).*{service}', iptables_output, re.IGNORECASE):
                        firewall_rules["allowed_services"].append(service)
            except:
                logger.warning("Failed to get iptables rules")
        
        elif platform.system() == 'Windows':
            try:
                # Use PowerShell to get firewall information
                output = subprocess.check_output("powershell -Command \"Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize\"", shell=True).decode()
                
                # Check if firewall is enabled
                if "True" in output:
                    # Get allowed programs
                    allowed_programs = subprocess.check_output("powershell -Command \"Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' } | Select-Object DisplayName | Format-Table -AutoSize\"", shell=True).decode()
                    
                    # Extract services from the output
                    for service in ["ssh", "rdp", "http", "https", "dns"]:
                        if re.search(service, allowed_programs, re.IGNORECASE):
                            firewall_rules["allowed_services"].append(service)
                    
                    firewall_rules["default_incoming"] = "block"  # Default Windows setting
                    firewall_rules["default_outgoing"] = "allow"  # Default Windows setting
            except:
                logger.warning("Failed to get Windows firewall rules")
        
        policies["firewall_rules"] = firewall_rules
    except Exception as e:
        logger.error(f"Error reading firewall rules: {str(e)}")
    
    # Add default policies where real ones couldn't be determined
    if "access_control" not in policies:
        policies["access_control"] = {
            "enforce_2fa": None,
            "session_timeout_minutes": None,
            "ip_whitelist_enabled": None,
            "privileged_access_review": None
        }
    
    if "data_protection" not in policies:
        policies["data_protection"] = {
            "encryption_at_rest": None,
            "encryption_in_transit": None,
            "data_classification_enforced": None,
            "data_retention_period_days": None
        }
    
    if "audit_logging" not in policies:
        policies["audit_logging"] = {
            "log_retention_days": None,
            "sensitive_action_logging": None,
            "log_review_frequency": None,
            "alert_on_suspicious": None
        }
    
    # Specific policy request
    policy_id = request.args.get('id')
    if policy_id:
        if policy_id in policies:
            return jsonify({policy_id: policies[policy_id]})
        else:
            return jsonify({"status": "error", "message": f"Policy {policy_id} not found"}), 404
    
    return jsonify(policies)

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
        'cat /etc/os-release', 'lsblk', 'ss -tuln',
        'systeminfo', 'tasklist', 'ipconfig', 'ping google.com -n 4', 'net stats',
        'ver', 'hostname', 'wmic os get version', 'dir', 'echo %PATH%'
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

# New endpoint for AI/ML log analysis
@app.route('/api/logs/ai-analysis', methods=['GET'])
def ai_log_analysis():
    log_path = request.args.get('path', '/var/log/syslog' if platform.system() == 'Linux' else 'System')
    limit = int(request.args.get('limit', 1000))
    
    try:
        # Get log entries (reuse the code from analyze_logs)
        if platform.system() == 'Linux':
            if log_path == 'System':
                log_path = '/var/log/syslog'
            elif log_path == 'Auth':
                log_path = '/var/log/auth.log'
            elif log_path == 'Kernel':
                log_path = '/var/log/kern.log'
            
            log_entries = read_system_logs(log_path, limit)
        
        elif platform.system() == 'Windows':
            if log_path == 'System':
                try:
                    output = subprocess.check_output(f"powershell -Command \"Get-EventLog -LogName System -Newest {limit} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json\"", shell=True).decode()
                    windows_logs = json.loads(output)
                    log_entries = []
                    
                    for entry in windows_logs:
                        log_entries.append({
                            "timestamp": entry["TimeGenerated"],
                            "level": entry["EntryType"],
                            "service": entry["Source"],
                            "message": entry["Message"]
                        })
                except:
                    log_entries = [{
                        "timestamp": datetime.datetime.now().isoformat(),
                        "level": "ERROR",
                        "service": "LogReader",
                        "message": "Failed to read system logs."
                    }]
            else:
                log_entries = read_system_logs(log_path, limit)
        else:
            log_entries = read_system_logs(log_path, limit)
        
        # Filter out None entries
        log_entries = [log for log in log_entries if log]
        
        # AI Analysis (simplified version)
        # In a real implementation, this would use ML libraries
        
        # 1. Time-based analysis
        time_buckets = {}
        for entry in log_entries:
            if entry["timestamp"]:
                try:
                    dt = datetime.datetime.fromisoformat(entry["timestamp"].replace('Z', '+00:00'))
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    if hour_key not in time_buckets:
                        time_buckets[hour_key] = {"total": 0, "error": 0, "warning": 0, "info": 0}
                    
                    time_buckets[hour_key]["total"] += 1
                    
                    if "ERROR" in entry["level"].upper():
                        time_buckets[hour_key]["error"] += 1
                    elif "WARN" in entry["level"].upper():
                        time_buckets[hour_key]["warning"] += 1
                    else:
                        time_buckets[hour_key]["info"] += 1
                except:
                    pass
        
        time_series = [{"time": k, "total": v["total"], "error": v["error"], "warning": v["warning"], "info": v["info"]} for k, v in time_buckets.items()]
        time_series.sort(key=lambda x: x["time"])
        
        # 2. Service distribution
        service_stats = {}
        for entry in log_entries:
            service = entry["service"]
            if service not in service_stats:
                service_stats[service] = {"total": 0, "error": 0, "warning": 0, "info": 0}
            
            service_stats[service]["total"] += 1
            
            if "ERROR" in entry["level"].upper():
                service_stats[service]["error"] += 1
            elif "WARN" in entry["level"].upper():
                service_stats[service]["warning"] += 1
            else:
                service_stats[service]["info"] += 1
        
        service_distribution = [{"name": k, "total": v["total"], "error": v["error"], "warning": v["warning"], "info": v["info"]} for k, v in service_stats.items()]
        service_distribution.sort(key=lambda x: x["total"], reverse=True)
        
        # 3. Error clustering (simplified)
        error_messages = [entry["message"] for entry in log_entries if "ERROR" in entry["level"].upper()]
        
        # Simple clustering by common words
        error_clusters = {}
        for msg in error_messages:
            # Get key words from message
            words = set(re.findall(r'\b\w{4,}\b', msg.lower()))
            key_words = " ".join(sorted(list(words)[:3]))
            
            if key_words not in error_clusters:
                error_clusters[key_words] = []
            
            error_clusters[key_words].append(msg)
        
        # Create clusters list
        clusters = [{"keywords": k, "count": len(v), "examples": v[:3]} for k, v in error_clusters.items()]
        clusters.sort(key=lambda x: x["count"], reverse=True)
        
        # 4. Anomaly detection (simplified)
        anomalies = []
        
        # Check for unusual error rates
        if time_series:
            error_rates = [x["error"] / max(x["total"], 1) for x in time_series]
            avg_error_rate = sum(error_rates) / len(error_rates)
            
            for point in time_series:
                error_rate = point["error"] / max(point["total"], 1)
                if error_rate > avg_error_rate * 3 and point["error"] > 5:  # Significant spike
                    anomalies.append({
                        "type": "error_spike",
                        "time": point["time"],
                        "error_rate": f"{error_rate:.2%}",
                        "normal_rate": f"{avg_error_rate:.2%}",
                        "deviation": f"{error_rate / max(avg_error_rate, 0.001):.1f}x normal"
                    })
        
        # 5. Pattern recognition
        patterns = {}
        for entry in log_entries:
            words = re.findall(r'\b\w{4,}\b', entry["message"].lower())
            for word in words:
                if word not in patterns:
                    patterns[word] = 0
                patterns[word] += 1
        
        # Find most common words
        top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:20]
        
        analysis_result = {
            "time_series": time_series,
            "service_distribution": service_distribution,
            "error_clusters": clusters[:10],
            "anomalies": anomalies,
            "top_patterns": top_patterns,
            "summary": {
                "total_logs": len(log_entries),
                "error_count": len([e for e in log_entries if "ERROR" in e["level"].upper()]),
                "warning_count": len([e for e in log_entries if "WARN" in e["level"].upper()]),
                "timespan": f"{time_series[0]['time']} to {time_series[-1]['time']}" if time_series else "unknown",
                "anomaly_count": len(anomalies)
            }
        }
        
        return jsonify(analysis_result)
    except Exception as e:
        logger.error(f"Error in AI log analysis: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

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
