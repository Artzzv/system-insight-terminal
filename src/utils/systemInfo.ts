
// This is a browser-compatible version of systemInfo.ts that uses mock data
// instead of direct system access through Node.js modules

// Mock function for executing shell commands (never really called in browser)
export const executeShellCommand = (command: string): Promise<string> => {
  console.log('Mock shell command:', command);
  return Promise.resolve(`Command executed: ${command}`);
};

// Get CPU information
export const getCpuInfo = () => {
  // Generate realistic mock CPU data
  const totalCores = navigator.hardwareConcurrency || 4;
  const physicalCores = Math.ceil(totalCores / 2);
  
  // Generate random CPU usage data per core
  const cpuUsagePerCore = Array(totalCores).fill(0).map(() => 
    Math.floor(Math.random() * 40) + 10
  );
  
  const totalCpuUsage = cpuUsagePerCore.reduce((sum, usage) => sum + usage, 0) / totalCores;
  
  return {
    physical_cores: physicalCores,
    total_cores: totalCores,
    cpu_usage_per_core: cpuUsagePerCore,
    total_cpu_usage: totalCpuUsage,
    cpu_frequency: {
      current: 2400 + Math.floor(Math.random() * 600),
      min: 1200,
      max: 3400
    },
    model: "Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz" // Example model name
  };
};

// Get memory information
export const getMemoryInfo = () => {
  // Generate realistic mock memory data
  const totalMemory = 16 * 1024 * 1024 * 1024; // 16 GB in bytes
  const usedPercent = 30 + Math.floor(Math.random() * 40); // 30-70%
  const usedMemory = Math.floor(totalMemory * (usedPercent / 100));
  const freeMemory = totalMemory - usedMemory;
  
  return {
    virtual_memory: {
      total: totalMemory,
      available: freeMemory,
      used: usedMemory,
      percentage: usedPercent
    },
    swap: {
      total: 4 * 1024 * 1024 * 1024, // 4 GB swap
      used: 512 * 1024 * 1024, // 512 MB used
      free: 3.5 * 1024 * 1024 * 1024, // Remaining
      percentage: 12.5
    }
  };
};

// Get disk information
export const getDiskInfo = async () => {
  // Generate realistic mock disk data
  const partitions = [
    {
      device: "C:",
      mountpoint: "C:",
      fstype: "NTFS",
      total_size: 512 * 1024 * 1024 * 1024, // 512 GB
      used: 256 * 1024 * 1024 * 1024, // 256 GB
      free: 256 * 1024 * 1024 * 1024, // 256 GB
      percentage: 50
    },
    {
      device: "D:",
      mountpoint: "D:",
      fstype: "NTFS",
      total_size: 1024 * 1024 * 1024 * 1024, // 1 TB
      used: 400 * 1024 * 1024 * 1024, // 400 GB
      free: 624 * 1024 * 1024 * 1024, // 624 GB
      percentage: 39
    }
  ];
  
  return { partitions };
};

// Get network information
export const getNetworkInfo = async () => {
  // Generate realistic mock network data
  const interfaces = {
    "Wi-Fi": {
      ip: "192.168.1.5",
      mac: "aa:bb:cc:dd:ee:ff",
      netmask: "255.255.255.0"
    },
    "Ethernet": {
      ip: "10.0.0.15",
      mac: "11:22:33:44:55:66",
      netmask: "255.255.0.0"
    }
  };
  
  // Generate mock network statistics
  const io_counters = {
    bytes_sent: 75000000 + Math.floor(Math.random() * 25000000),
    bytes_received: 150000000 + Math.floor(Math.random() * 50000000),
    packets_sent: 150000 + Math.floor(Math.random() * 50000),
    packets_received: 300000 + Math.floor(Math.random() * 100000)
  };
  
  // Generate mock connections
  const connections = [];
  const protocols = ["TCP", "UDP"];
  const statuses = ["ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", "LISTEN"];
  
  for (let i = 0; i < 15; i++) {
    connections.push({
      type: protocols[Math.floor(Math.random() * protocols.length)],
      local_address: `192.168.1.5:${10000 + Math.floor(Math.random() * 10000)}`,
      remote_address: `52.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}:${80 + Math.floor(Math.random() * 20)}`,
      status: statuses[Math.floor(Math.random() * statuses.length)]
    });
  }
  
  return {
    interfaces,
    io_counters,
    connections
  };
};

// Get system information
export const getSystemInfo = () => {
  const hostname = "Browser-" + Math.floor(Math.random() * 1000);
  const platform = navigator.platform || "Unknown";
  const bootTime = new Date(Date.now() - (Math.floor(Math.random() * 48) + 2) * 3600 * 1000);
  
  return {
    hostname,
    platform: platform + (platform.includes("Win") ? " 10" : " OS"),
    boot_time: bootTime.toISOString()
  };
};

// Security audit (simplified)
export const performSecurityAudit = async () => {
  const hostname = "Browser-" + Math.floor(Math.random() * 1000);
  const issueCount = Math.floor(Math.random() * 5);
  const issues = [];
  const issuesBySeverity = { high: 0, medium: 0, low: 0 };
  
  const possibleIssues = [
    {
      severity: 'high',
      issue: 'Critical security update pending',
      recommendation: 'Install latest security updates'
    },
    {
      severity: 'medium',
      issue: 'Outdated browser version detected',
      recommendation: 'Update your browser to the latest version'
    },
    {
      severity: 'medium',
      issue: 'Insecure network connection',
      recommendation: 'Use a VPN when connecting to public networks'
    },
    {
      severity: 'low',
      issue: 'Browser extensions have excessive permissions',
      recommendation: 'Review and limit permissions of browser extensions'
    },
    {
      severity: 'low',
      issue: 'Password manager not in use',
      recommendation: 'Use a secure password manager'
    }
  ];
  
  // Randomly select some issues
  for (let i = 0; i < issueCount; i++) {
    const randomIssue = possibleIssues[Math.floor(Math.random() * possibleIssues.length)];
    issues.push(randomIssue);
    issuesBySeverity[randomIssue.severity as keyof typeof issuesBySeverity]++;
    
    // Remove this issue so we don't select it again
    possibleIssues.splice(possibleIssues.indexOf(randomIssue), 1);
    
    if (possibleIssues.length === 0) break;
  }
  
  return {
    hostname,
    issues_by_severity: issuesBySeverity,
    issues
  };
};

// Log analysis (simplified)
export const analyzeLogs = async (logPath = 'System', limit = 100) => {
  // Generate mock log entries
  const entries = [];
  const levels = { info: 0, warning: 0, error: 0, critical: 0 };
  const services: Record<string, number> = {};
  const patterns: [string, number][] = [];
  
  // Create services
  const possibleServices = ['browser', 'network', 'security', 'system', 'application', 'database'];
  
  // Create time series data
  const timeSeriesCount = 24;
  const timeSeries = [];
  
  for (let i = 0; i < timeSeriesCount; i++) {
    const time = new Date(Date.now() - (timeSeriesCount - i) * 3600000).toISOString().slice(11, 16);
    const count = Math.floor(Math.random() * 10) + 1;
    timeSeries.push({ time, count });
  }
  
  // Create log entries
  for (let i = 0; i < limit; i++) {
    const timestamp = new Date(Date.now() - i * 60000).toISOString();
    const randomValue = Math.random();
    
    let level, service, message;
    
    if (randomValue < 0.7) {
      level = 'INFO';
      levels.info++;
    } else if (randomValue < 0.85) {
      level = 'WARNING';
      levels.warning++;
    } else if (randomValue < 0.95) {
      level = 'ERROR';
      levels.error++;
    } else {
      level = 'CRITICAL';
      levels.critical++;
    }
    
    service = possibleServices[Math.floor(Math.random() * possibleServices.length)];
    
    if (!services[service]) {
      services[service] = 0;
    }
    services[service]++;
    
    // Generate realistic messages based on level and service
    if (level === 'INFO') {
      const infoMessages = [
        `Service started successfully`,
        `System update check completed`,
        `User login successful`,
        `Successfully connected to network`,
        `Data synchronization completed`
      ];
      message = infoMessages[Math.floor(Math.random() * infoMessages.length)];
    } else if (level === 'WARNING') {
      const warningMessages = [
        `High CPU usage detected: ${Math.floor(Math.random() * 20) + 80}%`,
        `Memory usage approaching threshold: ${Math.floor(Math.random() * 10) + 70}%`,
        `Slow network response time`,
        `Failed login attempt`,
        `Service took longer than expected to respond`
      ];
      message = warningMessages[Math.floor(Math.random() * warningMessages.length)];
    } else if (level === 'ERROR') {
      const errorMessages = [
        `Failed to connect to server`,
        `Permission denied accessing resource`,
        `Unable to establish connection`,
        `Service crashed unexpectedly`,
        `Resource limit exceeded`
      ];
      message = errorMessages[Math.floor(Math.random() * errorMessages.length)];
    } else {
      const criticalMessages = [
        `System out of memory`,
        `Security breach detected`,
        `Critical service failure`,
        `Data corruption detected`,
        `Hardware failure detected`
      ];
      message = criticalMessages[Math.floor(Math.random() * criticalMessages.length)];
    }
    
    entries.push({
      timestamp,
      level,
      service,
      message
    });
  }
  
  // Find common patterns
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
    entries,
    levels,
    services,
    patterns,
    time_series: timeSeries
  };
};

// AI Log Analysis (more sophisticated analysis)
export const aiAnalyzeLogs = async (logPath = 'System', limit = 1000) => {
  // Get basic log analysis first
  const basicAnalysis = await analyzeLogs(logPath, limit);
  
  // Additional AI-style analysis
  const errorCount = basicAnalysis.levels.error + basicAnalysis.levels.critical;
  const warningCount = basicAnalysis.levels.warning;
  const infoCount = basicAnalysis.levels.info;
  const totalLogs = errorCount + warningCount + infoCount;
  
  // Generate time series with more data points
  const timeSeriesCount = 48;
  const timeSeries = [];
  
  for (let i = 0; i < timeSeriesCount; i++) {
    const time = new Date(Date.now() - (timeSeriesCount - i) * 1800000).toISOString().slice(11, 16);
    const base = Math.floor(Math.random() * 15) + 5;
    const error = Math.floor(Math.random() * 3);
    const warning = Math.floor(Math.random() * 5);
    
    timeSeries.push({ 
      time, 
      total: base + error + warning,
      error,
      warning
    });
  }
  
  // Create "anomalies" in time series
  const anomalyPoint = Math.floor(Math.random() * (timeSeriesCount - 10)) + 5;
  timeSeries[anomalyPoint].error = Math.floor(Math.random() * 10) + 15;
  timeSeries[anomalyPoint].total = timeSeries[anomalyPoint].total + timeSeries[anomalyPoint].error;
  
  // Detect services with most errors
  const serviceDistribution: any[] = [];
  Object.entries(basicAnalysis.services).forEach(([name, count]) => {
    const total = count as number;
    const error = Math.floor(Math.random() * (total * 0.2));
    const warning = Math.floor(Math.random() * (total * 0.3));
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
  const errorClusters = [
    {
      keywords: "Failed to connect",
      count: Math.floor(Math.random() * 10) + 5,
      examples: [
        "ERROR [network] Failed to connect to server: connection refused",
        "ERROR [database] Failed to connect to database: timeout after 30s",
        "ERROR [browser] Failed to connect to API endpoint"
      ]
    },
    {
      keywords: "Permission denied",
      count: Math.floor(Math.random() * 8) + 3,
      examples: [
        "ERROR [security] Permission denied accessing resource",
        "ERROR [application] Permission denied for user",
        "ERROR [system] Permission denied when accessing device"
      ]
    },
    {
      keywords: "Service crashed",
      count: Math.floor(Math.random() * 6) + 2,
      examples: [
        "ERROR [browser] Service crashed with exit code 1",
        "ERROR [application] Service crashed unexpectedly",
        "CRITICAL [database] Service crashed due to out of memory condition"
      ]
    }
  ];
  
  // Generate anomalies
  const anomalies = [
    {
      type: "error_spike",
      description: "Unusually high number of connection errors detected",
      time: timeSeries[anomalyPoint].time,
      deviation: "15x normal rate"
    }
  ];
  
  // Add another anomaly if error count is high enough
  if (errorCount > 10) {
    anomalies.push({
      type: "error_pattern",
      description: "Recurring permission denied errors may indicate misconfigured permissions",
      time: "",
      deviation: ""
    });
  }
  
  // Generate top patterns
  const topPatterns: [string, number][] = [
    ["connection failure", Math.floor(Math.random() * 20) + 10],
    ["system startup", Math.floor(Math.random() * 15) + 8],
    ["authentication failed", Math.floor(Math.random() * 12) + 5],
    ["network interface", Math.floor(Math.random() * 10) + 7],
    ["service restart", Math.floor(Math.random() * 8) + 6],
    ["memory usage", Math.floor(Math.random() * 7) + 4]
  ];
  
  return {
    summary: {
      total_logs: totalLogs,
      error_count: errorCount,
      warning_count: warningCount,
      anomaly_count: anomalies.length
    },
    time_series: timeSeries,
    service_distribution: serviceDistribution,
    error_clusters: errorClusters,
    anomalies,
    top_patterns: topPatterns
  };
};

// Get security policies
export const getSecurityPolicies = async () => {
  const passwordPolicy = {
    min_length: 8,
    require_uppercase: true,
    require_lowercase: true,
    require_numbers: true,
    require_special_chars: false,
    max_age_days: 90,
    prevent_reuse: true,
    lockout_threshold: 5
  };
  
  const firewallRules = {
    default_incoming: 'deny',
    default_outgoing: 'allow',
    allowed_services: ['http', 'https', 'dns']
  };
  
  return {
    password_policy: passwordPolicy,
    firewall_rules: firewallRules
  };
};
