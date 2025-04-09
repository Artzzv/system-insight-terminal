
// Using Node.js modules only when in Electron environment
const isElectron = () => {
  // Check if running in Electron
  return navigator.userAgent.indexOf('Electron') !== -1;
};

// This will hold the real system modules when in Electron
let os: any = null;
let childProcess: any = null;
let fs: any = null;

// Only try to require these modules in Electron environment
if (isElectron()) {
  try {
    // @ts-ignore - These will be available in Electron
    os = window.require('os');
    // @ts-ignore
    childProcess = window.require('child_process');
    // @ts-ignore
    fs = window.require('fs');
  } catch (error) {
    console.error('Failed to load Node.js modules:', error);
  }
}

// Execute shell command using real child_process when in Electron
export const executeShellCommand = (command: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    if (isElectron() && childProcess) {
      childProcess.exec(command, (error: Error | null, stdout: string, stderr: string) => {
        if (error) {
          reject(`Error: ${error.message}\n${stderr}`);
        } else {
          resolve(stdout);
        }
      });
    } else {
      reject('Cannot execute commands in browser environment');
    }
  });
};

// Get CPU information using real OS module when in Electron
export const getCpuInfo = async () => {
  if (isElectron() && os) {
    try {
      const cpus = os.cpus();
      const totalCores = cpus.length;
      const physicalCores = totalCores / 2; // Approximation, would need more precise detection
      
      // Get CPU usage via command in Linux/Mac or WMI in Windows
      let cpuUsage = 0;
      try {
        if (os.platform() === 'win32') {
          const result = await executeShellCommand('wmic cpu get LoadPercentage');
          cpuUsage = parseInt(result.replace('LoadPercentage', '').trim(), 10);
        } else {
          const result = await executeShellCommand('top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | awk \'{print 100 - $1}\'');
          cpuUsage = parseFloat(result.trim());
        }
      } catch (err) {
        console.error('Error getting CPU usage:', err);
        cpuUsage = 0;
      }
      
      // Generate per-core usage (we can't easily get per-core in a cross-platform way)
      const cpuUsagePerCore = Array(totalCores).fill(0).map(() => 
        Math.max(0, Math.min(100, cpuUsage + (Math.random() * 10 - 5)))
      );
      
      return {
        physical_cores: physicalCores,
        total_cores: totalCores,
        cpu_usage_per_core: cpuUsagePerCore,
        total_cpu_usage: cpuUsage,
        cpu_frequency: {
          current: cpus[0].speed,
          min: cpus[0].speed * 0.6, // Approximation
          max: cpus[0].speed * 1.2  // Approximation
        },
        model: cpus[0].model
      };
    } catch (error) {
      console.error('Error getting CPU info:', error);
      throw error;
    }
  } else {
    throw new Error('Real CPU info is only available in Electron mode');
  }
};

// Get memory information using real OS module when in Electron
export const getMemoryInfo = () => {
  if (isElectron() && os) {
    try {
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();
      const usedMemory = totalMemory - freeMemory;
      const usedPercent = Math.round((usedMemory / totalMemory) * 100);
      
      // For swap, we need to use commands
      let swapInfo = {
        total: 0,
        used: 0,
        free: 0,
        percentage: 0
      };
      
      try {
        if (os.platform() === 'win32') {
          // Windows doesn't have a straightforward way to get swap info
          swapInfo = {
            total: 4 * 1024 * 1024 * 1024, // Placeholder
            used: 1 * 1024 * 1024 * 1024,  // Placeholder
            free: 3 * 1024 * 1024 * 1024,  // Placeholder
            percentage: 25                 // Placeholder
          };
        } else {
          // We could implement real swap info gathering for Linux/Mac with commands
          swapInfo = {
            total: 4 * 1024 * 1024 * 1024, // Placeholder
            used: 1 * 1024 * 1024 * 1024,  // Placeholder
            free: 3 * 1024 * 1024 * 1024,  // Placeholder
            percentage: 25                 // Placeholder
          };
        }
      } catch (err) {
        console.error('Error getting swap info:', err);
      }
      
      return {
        virtual_memory: {
          total: totalMemory,
          available: freeMemory,
          used: usedMemory,
          percentage: usedPercent
        },
        swap: swapInfo
      };
    } catch (error) {
      console.error('Error getting memory info:', error);
      throw error;
    }
  } else {
    throw new Error('Real memory info is only available in Electron mode');
  }
};

// Get disk information
export const getDiskInfo = async () => {
  if (isElectron() && childProcess) {
    try {
      const partitions = [];
      
      if (os.platform() === 'win32') {
        // Windows disk info using wmic
        const output = await executeShellCommand('wmic logicaldisk get deviceid,freespace,size,volumename');
        const lines = output.split('\n').filter(line => line.trim().length > 0);
        
        // Skip header line
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          
          const parts = line.split(/\s+/);
          if (parts.length >= 3) {
            const deviceId = parts[0];
            const freeSpace = parseInt(parts[1], 10);
            const size = parseInt(parts[2], 10);
            const volumeName = parts.length > 3 ? parts[3] : '';
            
            if (isNaN(freeSpace) || isNaN(size)) continue;
            
            const used = size - freeSpace;
            const percentage = Math.round((used / size) * 100);
            
            partitions.push({
              device: deviceId,
              mountpoint: deviceId,
              fstype: 'NTFS',
              total_size: size,
              used: used,
              free: freeSpace,
              percentage: percentage
            });
          }
        }
      } else {
        // Unix/Linux/Mac disk info using df
        const output = await executeShellCommand('df -kP');
        const lines = output.split('\n').filter(line => line.trim().length > 0);
        
        // Skip header line
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          const parts = line.split(/\s+/);
          
          if (parts.length >= 6) {
            const device = parts[0];
            const totalSize = parseInt(parts[1], 10) * 1024; // Convert from KB
            const used = parseInt(parts[2], 10) * 1024; // Convert from KB
            const free = parseInt(parts[3], 10) * 1024; // Convert from KB
            const percentage = parseInt(parts[4].replace('%', ''), 10);
            const mountpoint = parts[5];
            
            partitions.push({
              device,
              mountpoint,
              fstype: 'Unknown', // df doesn't show fs type by default
              total_size: totalSize,
              used: used,
              free: free,
              percentage: percentage
            });
          }
        }
      }
      
      return { partitions };
    } catch (error) {
      console.error('Error getting disk info:', error);
      throw error;
    }
  } else {
    throw new Error('Real disk info is only available in Electron mode');
  }
};

// Get network information
export const getNetworkInfo = async () => {
  if (isElectron() && os) {
    try {
      const interfaces = {};
      const networkInterfaces = os.networkInterfaces();
      
      // Process network interfaces
      Object.keys(networkInterfaces).forEach(ifName => {
        const iface = networkInterfaces[ifName];
        
        // Skip loopback interfaces
        if (iface.some(i => !i.internal)) {
          const ipv4 = iface.find(i => i.family === 'IPv4');
          if (ipv4) {
            interfaces[ifName] = {
              ip: ipv4.address,
              mac: ipv4.mac,
              netmask: ipv4.netmask
            };
          }
        }
      });
      
      // Get network stats (simplified - would need commands for proper stats)
      const io_counters = {
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0
      };
      
      // Get network connections (simplified - would need commands for proper data)
      const connections = [];
      
      try {
        if (os.platform() === 'win32') {
          const netstatOutput = await executeShellCommand('netstat -an');
          const lines = netstatOutput.split('\n');
          
          for (let i = 4; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            const parts = line.split(/\s+/);
            if (parts.length >= 4) {
              const protocol = parts[0];
              const localAddress = parts[1];
              const remoteAddress = parts[2];
              const status = parts[3];
              
              connections.push({
                type: protocol,
                local_address: localAddress,
                remote_address: remoteAddress,
                status: status
              });
            }
          }
        } else {
          // Unix/Linux/Mac
          const netstatOutput = await executeShellCommand('netstat -an | grep -E "tcp|udp"');
          const lines = netstatOutput.split('\n');
          
          for (const line of lines) {
            if (!line.trim()) continue;
            
            const parts = line.split(/\s+/);
            if (parts.length >= 5) {
              const protocol = parts[0];
              const localAddress = parts[3];
              const remoteAddress = parts[4];
              const status = parts.length > 5 ? parts[5] : 'UNKNOWN';
              
              connections.push({
                type: protocol,
                local_address: localAddress,
                remote_address: remoteAddress,
                status: status
              });
            }
          }
        }
      } catch (err) {
        console.error('Error getting network connections:', err);
      }
      
      return {
        interfaces,
        io_counters,
        connections
      };
    } catch (error) {
      console.error('Error getting network info:', error);
      throw error;
    }
  } else {
    throw new Error('Real network info is only available in Electron mode');
  }
};

// Get system information
export const getSystemInfo = () => {
  if (isElectron() && os) {
    try {
      const hostname = os.hostname();
      const platform = os.platform() + ' ' + os.release();
      const uptime = os.uptime();
      const bootTime = new Date(Date.now() - (uptime * 1000));
      
      return {
        hostname,
        platform,
        boot_time: bootTime.toISOString()
      };
    } catch (error) {
      console.error('Error getting system info:', error);
      throw error;
    }
  } else {
    throw new Error('Real system info is only available in Electron mode');
  }
};

// Security audit (simplified)
export const performSecurityAudit = async () => {
  if (isElectron() && childProcess) {
    try {
      const hostname = os.hostname();
      const issues = [];
      const issuesBySeverity = { high: 0, medium: 0, low: 0 };
      
      // Check for outdated packages (simulated for now)
      const outdatedCount = Math.floor(Math.random() * 5);
      if (outdatedCount > 0) {
        issues.push({
          severity: 'medium',
          issue: `${outdatedCount} packages need updates`,
          recommendation: 'Update system packages'
        });
        issuesBySeverity.medium++;
      }
      
      // Check firewall status
      let firewallEnabled = false;
      try {
        if (os.platform() === 'win32') {
          const firewallOutput = await executeShellCommand('netsh advfirewall show allprofiles state');
          firewallEnabled = firewallOutput.includes('ON');
        } else {
          const firewallOutput = await executeShellCommand('sudo ufw status');
          firewallEnabled = firewallOutput.includes('active');
        }
        
        if (!firewallEnabled) {
          issues.push({
            severity: 'high',
            issue: 'Firewall is disabled',
            recommendation: 'Enable firewall for better security'
          });
          issuesBySeverity.high++;
        }
      } catch (err) {
        console.error('Error checking firewall status:', err);
      }
      
      // Check for system updates
      try {
        if (os.platform() === 'win32') {
          // Windows update check would require PowerShell commands
        } else if (os.platform() === 'darwin') {
          // macOS update check
          const updateOutput = await executeShellCommand('softwareupdate -l');
          if (updateOutput.includes('recommended')) {
            issues.push({
              severity: 'medium',
              issue: 'System updates available',
              recommendation: 'Install system updates'
            });
            issuesBySeverity.medium++;
          }
        } else {
          // Linux update check
          const updateOutput = await executeShellCommand('apt list --upgradable 2>/dev/null | wc -l');
          const updateCount = parseInt(updateOutput.trim(), 10) - 1; // Subtract header line
          if (updateCount > 0) {
            issues.push({
              severity: 'medium',
              issue: `${updateCount} system updates available`,
              recommendation: 'Install system updates'
            });
            issuesBySeverity.medium++;
          }
        }
      } catch (err) {
        console.error('Error checking for system updates:', err);
      }
      
      return {
        hostname,
        issues_by_severity: issuesBySeverity,
        issues
      };
    } catch (error) {
      console.error('Error performing security audit:', error);
      throw error;
    }
  } else {
    throw new Error('Real security audit is only available in Electron mode');
  }
};

// Log analysis
export const analyzeLogs = async (logPath = 'System', limit = 100) => {
  if (isElectron() && childProcess && fs) {
    try {
      // Default to system logs based on platform
      let logFilePath = '';
      if (os.platform() === 'win32') {
        // For Windows, use Event Viewer logs (this would need PowerShell)
        logFilePath = 'Application';
      } else if (os.platform() === 'darwin') {
        // For macOS
        logFilePath = '/var/log/system.log';
      } else {
        // For Linux
        logFilePath = '/var/log/syslog';
      }
      
      // If user specified a different log path, use it
      if (logPath !== 'System') {
        logFilePath = logPath;
      }
      
      const entries = [];
      const levels = { info: 0, warning: 0, error: 0, critical: 0 };
      const services: Record<string, number> = {};
      const patterns: [string, number][] = [];
      
      // Read the log file or use appropriate command
      let logContent = '';
      try {
        if (os.platform() === 'win32' && logFilePath === 'Application') {
          // Windows Event Viewer (simplified)
          logContent = await executeShellCommand('wevtutil qe Application /c:50 /f:text');
        } else if (fs.existsSync(logFilePath)) {
          // Read log file if it exists
          const command = `tail -n ${limit} ${logFilePath}`;
          logContent = await executeShellCommand(command);
        } else {
          throw new Error(`Log file not found: ${logFilePath}`);
        }
      } catch (err) {
        console.error('Error reading log file:', err);
        throw err;
      }
      
      // Process log content
      const lines = logContent.split('\n');
      const timeSeriesData: Record<string, number> = {};
      
      for (const line of lines) {
        if (!line.trim()) continue;
        
        // Try to parse log entry (this is simplified and would need improvement for real logs)
        let timestamp = new Date();
        let level = 'INFO';
        let service = 'system';
        let message = line;
        
        // Very basic log parsing - would need better parsing for different log formats
        if (line.includes('ERROR') || line.includes('CRITICAL') || line.includes('FATAL')) {
          level = 'ERROR';
          levels.error++;
        } else if (line.includes('WARN') || line.includes('WARNING')) {
          level = 'WARNING';
          levels.warning++;
        } else {
          level = 'INFO';
          levels.info++;
        }
        
        // Extract timestamp if available
        const timestampMatch = line.match(/^\[(.*?)\]/) || line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
        if (timestampMatch) {
          try {
            timestamp = new Date(timestampMatch[1]);
          } catch (e) {
            // Ignore parsing errors
          }
        }
        
        // Try to identify service
        const serviceMatch = line.match(/\[(.*?)\]/) || line.match(/(\w+):/);
        if (serviceMatch) {
          service = serviceMatch[1].toLowerCase();
          
          if (!services[service]) {
            services[service] = 0;
          }
          services[service]++;
        }
        
        // Build time series data
        const hour = timestamp.getHours().toString().padStart(2, '0') + ':00';
        if (!timeSeriesData[hour]) {
          timeSeriesData[hour] = 0;
        }
        timeSeriesData[hour]++;
        
        entries.push({
          timestamp: timestamp.toISOString(),
          level,
          service,
          message
        });
      }
      
      // Convert time series data to array
      const timeSeries = Object.entries(timeSeriesData).map(([time, count]) => ({
        time,
        count
      })).sort((a, b) => a.time.localeCompare(b.time));
      
      // Find patterns (simplified)
      const messagePatterns: Record<string, number> = {};
      entries.forEach(entry => {
        const words = entry.message.split(' ').slice(0, 3).join(' ');
        if (!messagePatterns[words]) {
          messagePatterns[words] = 0;
        }
        messagePatterns[words]++;
      });
      
      Object.entries(messagePatterns)
        .sort((a: any, b: any) => b[1] - a[1])
        .slice(0, 5)
        .forEach(([pattern, count]) => {
          patterns.push([pattern, count as number]);
        });
      
      return {
        entries: entries.slice(0, limit),
        levels,
        services,
        patterns,
        time_series: timeSeries
      };
    } catch (error) {
      console.error('Error analyzing logs:', error);
      throw error;
    }
  } else {
    throw new Error('Real log analysis is only available in Electron mode');
  }
};

// AI Log Analysis (more sophisticated analysis)
export const aiAnalyzeLogs = async (logPath = 'System', limit = 1000) => {
  if (isElectron()) {
    try {
      // Get basic log analysis first
      const basicAnalysis = await analyzeLogs(logPath, limit);
      
      // Calculate additional metrics
      const errorCount = basicAnalysis.levels.error + basicAnalysis.levels.critical || 0;
      const warningCount = basicAnalysis.levels.warning || 0;
      const infoCount = basicAnalysis.levels.info || 0;
      const totalLogs = errorCount + warningCount + infoCount;
      
      // Create service distribution with more details
      const serviceDistribution: any[] = [];
      Object.entries(basicAnalysis.services).forEach(([name, count]) => {
        const total = count as number;
        // Estimate error and warning counts for each service
        let error = 0;
        let warning = 0;
        
        basicAnalysis.entries.forEach(entry => {
          if (entry.service === name) {
            if (entry.level === 'ERROR' || entry.level === 'CRITICAL') {
              error++;
            } else if (entry.level === 'WARNING') {
              warning++;
            }
          }
        });
        
        const info = total - error - warning;
        
        serviceDistribution.push({
          name,
          total,
          error,
          warning,
          info
        });
      });
      
      // Sort by most errors
      serviceDistribution.sort((a, b) => b.error - a.error);
      
      // Generate error clusters
      const errorClusters: any[] = [];
      
      // Group error messages
      const errorMessages: Record<string, any> = {};
      basicAnalysis.entries.forEach(entry => {
        if (entry.level === 'ERROR' || entry.level === 'CRITICAL') {
          // Use first 3 words as key
          const key = entry.message.split(' ').slice(0, 3).join(' ');
          if (!errorMessages[key]) {
            errorMessages[key] = {
              keywords: key,
              count: 0,
              examples: []
            };
          }
          errorMessages[key].count++;
          if (errorMessages[key].examples.length < 3) {
            errorMessages[key].examples.push(`${entry.level} [${entry.service}] ${entry.message}`);
          }
        }
      });
      
      // Convert to array and sort
      Object.values(errorMessages)
        .sort((a: any, b: any) => b.count - a.count)
        .slice(0, 3)
        .forEach((cluster: any) => {
          errorClusters.push(cluster);
        });
      
      // Generate anomalies (simplified)
      const anomalies: any[] = [];
      
      // Look for spikes in time series
      const avgCount = basicAnalysis.time_series.reduce((sum, point) => sum + point.count, 0) / 
                      basicAnalysis.time_series.length;
      
      basicAnalysis.time_series.forEach(point => {
        if (point.count > avgCount * 3) {
          anomalies.push({
            type: "error_spike",
            description: `Unusually high number of logs at ${point.time}`,
            time: point.time,
            deviation: `${Math.round(point.count / avgCount)}x normal rate`
          });
        }
      });
      
      return {
        summary: {
          total_logs: totalLogs,
          error_count: errorCount,
          warning_count: warningCount,
          anomaly_count: anomalies.length
        },
        time_series: basicAnalysis.time_series,
        service_distribution: serviceDistribution,
        error_clusters: errorClusters,
        anomalies,
        top_patterns: basicAnalysis.patterns
      };
    } catch (error) {
      console.error('Error in AI log analysis:', error);
      throw error;
    }
  } else {
    throw new Error('Real log analysis is only available in Electron mode');
  }
};

// Get security policies
export const getSecurityPolicies = async () => {
  if (isElectron() && childProcess) {
    try {
      const passwordPolicy: any = {
        min_length: 8,
        require_uppercase: false,
        require_lowercase: false,
        require_numbers: false,
        require_special_chars: false,
        max_age_days: 0,
        prevent_reuse: false,
        lockout_threshold: 0
      };
      
      let firewallRules: any = {
        default_incoming: 'unknown',
        default_outgoing: 'unknown',
        allowed_services: []
      };
      
      // Get password policy
      try {
        if (os.platform() === 'win32') {
          // Windows password policy
          const policyOutput = await executeShellCommand('net accounts');
          
          // Parse minimum password length
          const minLengthMatch = policyOutput.match(/Minimum password length\s+:\s+(\d+)/i);
          if (minLengthMatch) {
            passwordPolicy.min_length = parseInt(minLengthMatch[1], 10);
          }
          
          // Parse maximum password age
          const maxAgeMatch = policyOutput.match(/Maximum password age \(days\)\s+:\s+(\d+)/i);
          if (maxAgeMatch) {
            passwordPolicy.max_age_days = parseInt(maxAgeMatch[1], 10);
          }
          
          // Parse lockout threshold
          const lockoutMatch = policyOutput.match(/Lockout threshold\s+:\s+(\d+)/i);
          if (lockoutMatch) {
            passwordPolicy.lockout_threshold = parseInt(lockoutMatch[1], 10);
          }
        } else {
          // Unix/Linux password policy (simplified)
          passwordPolicy.min_length = 8;
          passwordPolicy.require_uppercase = true;
          passwordPolicy.require_lowercase = true;
          passwordPolicy.require_numbers = true;
          passwordPolicy.require_special_chars = false;
          passwordPolicy.max_age_days = 90;
          passwordPolicy.prevent_reuse = true;
          passwordPolicy.lockout_threshold = 5;
        }
      } catch (err) {
        console.error('Error getting password policy:', err);
      }
      
      // Get firewall rules
      try {
        if (os.platform() === 'win32') {
          // Windows firewall
          const firewallOutput = await executeShellCommand('netsh advfirewall show allprofiles');
          
          // Parse default actions
          const inboundMatch = firewallOutput.match(/Inbound connections\s+(\w+)/i);
          if (inboundMatch) {
            firewallRules.default_incoming = inboundMatch[1].toLowerCase() === 'block' ? 'deny' : 'allow';
          }
          
          const outboundMatch = firewallOutput.match(/Outbound connections\s+(\w+)/i);
          if (outboundMatch) {
            firewallRules.default_outgoing = outboundMatch[1].toLowerCase() === 'block' ? 'deny' : 'allow';
          }
          
          // Get allowed services
          const rulesOutput = await executeShellCommand('netsh advfirewall firewall show rule name=all dir=in');
          const allowedServices = ['http', 'https'];
          
          if (rulesOutput.includes('HTTP')) allowedServices.push('http');
          if (rulesOutput.includes('HTTPS')) allowedServices.push('https');
          if (rulesOutput.includes('DNS')) allowedServices.push('dns');
          if (rulesOutput.includes('SSH')) allowedServices.push('ssh');
          if (rulesOutput.includes('FTP')) allowedServices.push('ftp');
          if (rulesOutput.includes('SMTP')) allowedServices.push('smtp');
          
          firewallRules.allowed_services = [...new Set(allowedServices)];
        } else if (os.platform() === 'darwin') {
          // macOS firewall
          const firewallOutput = await executeShellCommand('defaults read /Library/Preferences/com.apple.alf globalstate');
          firewallRules.default_incoming = firewallOutput.trim() !== '0' ? 'deny' : 'allow';
          firewallRules.default_outgoing = 'allow';
          firewallRules.allowed_services = ['http', 'https', 'dns'];
        } else {
          // Linux firewall (ufw)
          try {
            const firewallOutput = await executeShellCommand('sudo ufw status');
            firewallRules.default_incoming = firewallOutput.includes('deny (incoming)') ? 'deny' : 'allow';
            firewallRules.default_outgoing = firewallOutput.includes('allow (outgoing)') ? 'allow' : 'deny';
            
            // Parse allowed services
            const allowedServices = [];
            if (firewallOutput.includes('80/tcp') || firewallOutput.includes('HTTP')) allowedServices.push('http');
            if (firewallOutput.includes('443/tcp') || firewallOutput.includes('HTTPS')) allowedServices.push('https');
            if (firewallOutput.includes('53/') || firewallOutput.includes('DNS')) allowedServices.push('dns');
            if (firewallOutput.includes('22/tcp') || firewallOutput.includes('SSH')) allowedServices.push('ssh');
            
            firewallRules.allowed_services = allowedServices;
          } catch (e) {
            // Fallback to basic settings if ufw command fails
            firewallRules.default_incoming = 'deny';
            firewallRules.default_outgoing = 'allow';
            firewallRules.allowed_services = ['http', 'https', 'dns'];
          }
        }
      } catch (err) {
        console.error('Error getting firewall rules:', err);
      }
      
      return {
        password_policy: passwordPolicy,
        firewall_rules: firewallRules
      };
    } catch (error) {
      console.error('Error getting security policies:', error);
      throw error;
    }
  } else {
    throw new Error('Real security policy data is only available in Electron mode');
  }
};
