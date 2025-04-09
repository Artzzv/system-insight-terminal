// Import the isElectron function from our utility file
import { isElectron } from './isElectron';

// Define types for our system information
export interface SystemInfo {
  hostname: string;
  platform: string;
  arch?: string;
  cpus?: any[];
  totalmem?: number;
  freemem?: number;
  uptime?: number;
  boot_time: string;
}

export interface CpuInfo {
  physical_cores: number;
  total_cores: number;
  cpu_usage_per_core: number[];
  total_cpu_usage: number;
  cpu_frequency: {
    current: number;
    min: number;
    max: number;
  };
  model: string;
}

export interface MemoryInfo {
  virtual_memory: {
    total: number;
    available: number;
    used: number;
    percentage: number;
  };
  swap: {
    total: number;
    used: number;
    free: number;
    percentage: number;
  };
}

export interface DiskInfo {
  partitions: Array<{
    device: string;
    mountpoint: string;
    fstype: string;
    total_size: number;
    used: number;
    free: number;
    percentage: number;
  }>;
}

export interface NetworkInfo {
  interfaces: Record<string, {
    ip: string;
    mac: string;
    netmask: string;
  }>;
  io_counters: {
    bytes_sent: number;
    bytes_received: number;
    packets_sent: number;
    packets_received: number;
  };
  connections: Array<{
    type: string;
    local_address: string;
    remote_address: string;
    status: string;
  }>;
}

export interface SecurityAuditResult {
  hostname: string;
  issues_by_severity: {
    high: number;
    medium: number;
    low: number;
  };
  issues: Array<{
    severity: string;
    issue: string;
    recommendation: string;
  }>;
}

// This will hold the real system modules when in Electron
let os: any = null;
let childProcess: any = null;
let fs: any = null;

// Only try to require these modules in Electron environment
if (isElectron()) {
  try {
    // @ts-ignore - These will be available in Electron through the preload script
    const api = window.api;
    if (api && api.node) {
      os = api.node.os();
      childProcess = api.node.childProcess();
      fs = api.node.fs();
    }
  } catch (error) {
    console.error('Failed to load Node.js modules:', error);
  }
}

// Execute shell command using real child_process when in Electron
export const executeShellCommand = (command: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    if (isElectron()) {
      // Use IPC for executing commands instead of direct access
      try {
        // @ts-ignore
        window.api.send('execute-command', command);
        // @ts-ignore
        window.api.receive('command-result', (result: any) => {
          if (result.success) {
            resolve(result.stdout);
          } else {
            reject(`Error: ${result.error}\n${result.stderr}`);
          }
        });
      } catch (error) {
        reject(`Failed to execute command: ${(error as Error).message}`);
      }
    } else {
      reject('Cannot execute commands in browser environment');
    }
  });
};

// Get CPU information using real OS module when in Electron
export const getCpuInfo = async (): Promise<CpuInfo> => {
  if (isElectron()) {
    try {
      return new Promise<CpuInfo>((resolve) => {
        // @ts-ignore
        window.api.send('get-cpu-info');
        // @ts-ignore
        window.api.receive('cpu-info', (cpuInfo: CpuInfo) => {
          resolve(cpuInfo);
        });
      });
    } catch (error) {
      console.error('Error getting CPU info:', error);
      throw error;
    }
  } else {
    // Return mock data for browser environment
    return {
      physical_cores: 4,
      total_cores: 8,
      cpu_usage_per_core: Array(8).fill(0).map(() => Math.floor(Math.random() * 100)),
      total_cpu_usage: Math.floor(Math.random() * 100),
      cpu_frequency: {
        current: 2600,
        min: 1600,
        max: 3200
      },
      model: "CPU Model X (Browser Mode)"
    };
  }
};

// Get memory information using real OS module when in Electron
export const getMemoryInfo = (): Promise<MemoryInfo> => {
  if (isElectron()) {
    try {
      return new Promise<MemoryInfo>((resolve) => {
        // @ts-ignore
        window.api.send('get-memory-info');
        // @ts-ignore
        window.api.receive('memory-info', (memInfo: MemoryInfo) => {
          resolve(memInfo);
        });
      });
    } catch (error) {
      console.error('Error getting memory info:', error);
      throw error;
    }
  } else {
    // Return mock data for browser environment
    const totalMemory = 16 * 1024 * 1024 * 1024; // 16GB
    const freeMemory = Math.floor(Math.random() * totalMemory * 0.7);
    const usedMemory = totalMemory - freeMemory;
    const usedPercent = Math.round((usedMemory / totalMemory) * 100);
    
    return Promise.resolve({
      virtual_memory: {
        total: totalMemory,
        available: freeMemory,
        used: usedMemory,
        percentage: usedPercent
      },
      swap: {
        total: 4 * 1024 * 1024 * 1024,
        used: 1 * 1024 * 1024 * 1024,
        free: 3 * 1024 * 1024 * 1024,
        percentage: 25
      }
    });
  }
};

// Get disk information
export const getDiskInfo = async (): Promise<DiskInfo> => {
  if (isElectron()) {
    try {
      return new Promise<DiskInfo>((resolve) => {
        // We could implement IPC for disk info
        // For now, return simulated data
        setTimeout(() => {
          resolve({
            partitions: [
              {
                device: 'C:',
                mountpoint: 'C:',
                fstype: 'NTFS',
                total_size: 512 * 1024 * 1024 * 1024,
                used: 256 * 1024 * 1024 * 1024,
                free: 256 * 1024 * 1024 * 1024,
                percentage: 50
              }
            ]
          });
        }, 500);
      });
    } catch (error) {
      console.error('Error getting disk info:', error);
      throw error;
    }
  } else {
    // Return mock data for browser environment
    return Promise.resolve({
      partitions: [
        {
          device: 'C:',
          mountpoint: 'C:',
          fstype: 'NTFS',
          total_size: 512 * 1024 * 1024 * 1024,
          used: 256 * 1024 * 1024 * 1024,
          free: 256 * 1024 * 1024 * 1024,
          percentage: 50
        }
      ]
    });
  }
};

// Get network information
export const getNetworkInfo = async (): Promise<NetworkInfo> => {
  if (isElectron()) {
    try {
      // Implementation for real network info via IPC would go here
      // For now, return simulated data
      return {
        interfaces: {
          'eth0': {
            ip: '192.168.1.100',
            mac: '00:11:22:33:44:55',
            netmask: '255.255.255.0'
          }
        },
        io_counters: {
          bytes_sent: 1024 * 1024 * 50,
          bytes_received: 1024 * 1024 * 100,
          packets_sent: 5000,
          packets_received: 8000
        },
        connections: Array(5).fill(0).map((_, i) => ({
          type: 'TCP',
          local_address: `127.0.0.1:${8000 + i}`,
          remote_address: `192.168.1.${10 + i}:80`,
          status: i % 2 ? 'ESTABLISHED' : 'LISTEN'
        }))
      };
    } catch (error) {
      console.error('Error getting network info:', error);
      throw error;
    }
  } else {
    // Return mock data for browser environment
    return Promise.resolve({
      interfaces: {
        'eth0': {
          ip: '192.168.1.100',
          mac: '00:11:22:33:44:55',
          netmask: '255.255.255.0'
        }
      },
      io_counters: {
        bytes_sent: 1024 * 1024 * 50,
        bytes_received: 1024 * 1024 * 100,
        packets_sent: 5000,
        packets_received: 8000
      },
      connections: Array(5).fill(0).map((_, i) => ({
        type: 'TCP',
        local_address: `127.0.0.1:${8000 + i}`,
        remote_address: `192.168.1.${10 + i}:80`,
        status: i % 2 ? 'ESTABLISHED' : 'LISTEN'
      }))
    });
  }
};

// Get system information
export const getSystemInfo = (): Promise<SystemInfo> => {
  if (isElectron()) {
    try {
      return new Promise<SystemInfo>((resolve) => {
        // @ts-ignore
        window.api.send('get-system-info');
        // @ts-ignore
        window.api.receive('system-info', (sysInfo: SystemInfo) => {
          resolve(sysInfo);
        });
      });
    } catch (error) {
      console.error('Error getting system info:', error);
      throw error;
    }
  } else {
    // Return mock data for browser environment
    const bootTime = new Date();
    bootTime.setHours(bootTime.getHours() - 24); // 24 hours uptime
    
    return Promise.resolve({
      hostname: 'browser-host',
      platform: 'Browser (Simulated)',
      boot_time: bootTime.toISOString()
    });
  }
};

// Security audit (simplified)
export const performSecurityAudit = async (): Promise<SecurityAuditResult> => {
  if (isElectron()) {
    try {
      // Implementation for real security audit via IPC would go here
      // For now, return simulated data
      return {
        hostname: 'system',
        issues_by_severity: { high: 1, medium: 2, low: 3 },
        issues: [
          {
            severity: 'high',
            issue: 'Firewall is disabled',
            recommendation: 'Enable firewall for better security'
          },
          {
            severity: 'medium',
            issue: 'System updates available',
            recommendation: 'Install system updates'
          },
          {
            severity: 'low',
            issue: 'Non-essential services running',
            recommendation: 'Disable unnecessary services'
          }
        ]
      };
    } catch (error) {
      console.error('Error performing security audit:', error);
      throw error;
    }
  } else {
    // Return mock data for browser environment
    return Promise.resolve({
      hostname: 'browser-host',
      issues_by_severity: { high: 1, medium: 2, low: 3 },
      issues: [
        {
          severity: 'high',
          issue: 'Firewall is disabled',
          recommendation: 'Enable firewall for better security'
        },
        {
          severity: 'medium',
          issue: 'System updates available',
          recommendation: 'Install system updates'
        },
        {
          severity: 'low',
          issue: 'Non-essential services running',
          recommendation: 'Disable unnecessary services'
        }
      ]
    });
  }
};

// Log analysis
export const analyzeLogs = async (logPath = 'System', limit = 100) => {
  // Mock implementation
  return {
    entries: Array(10).fill(0).map((_, i) => ({
      timestamp: new Date().toISOString(),
      level: ['INFO', 'WARNING', 'ERROR'][Math.floor(Math.random() * 3)],
      service: ['system', 'network', 'security'][Math.floor(Math.random() * 3)],
      message: `Log message ${i+1}`
    })),
    levels: { info: 7, warning: 2, error: 1, critical: 0 },
    services: { system: 5, network: 3, security: 2 },
    patterns: [['System started', 2], ['Connection established', 3]],
    time_series: Array(24).fill(0).map((_, i) => ({
      time: `${i.toString().padStart(2, '0')}:00`,
      count: Math.floor(Math.random() * 10)
    }))
  };
};

// AI Log Analysis (more sophisticated analysis)
export const aiAnalyzeLogs = async (logPath = 'System', limit = 1000) => {
  // Mock implementation
  return {
    summary: {
      total_logs: 1000,
      error_count: 50,
      warning_count: 150,
      anomaly_count: 3
    },
    time_series: Array(24).fill(0).map((_, i) => ({
      time: `${i.toString().padStart(2, '0')}:00`,
      count: Math.floor(Math.random() * 100)
    })),
    service_distribution: [
      { name: 'system', total: 400, error: 20, warning: 50, info: 330 },
      { name: 'network', total: 300, error: 15, warning: 45, info: 240 },
      { name: 'security', total: 200, error: 10, warning: 40, info: 150 }
    ],
    error_clusters: [
      {
        keywords: 'Connection refused at',
        count: 15,
        examples: ['ERROR [network] Connection refused at 192.168.1.1:80']
      }
    ],
    anomalies: [
      {
        type: 'error_spike',
        description: 'Unusually high number of logs at 14:00',
        time: '14:00',
        deviation: '3x normal rate'
      }
    ],
    top_patterns: [['Connection refused', 15], ['Authentication failed', 10]]
  };
};

// Get security policies
export const getSecurityPolicies = async () => {
  // Mock implementation
  return {
    password_policy: {
      min_length: 8,
      require_uppercase: true,
      require_lowercase: true,
      require_numbers: true,
      require_special_chars: false,
      max_age_days: 90,
      prevent_reuse: true,
      lockout_threshold: 5
    },
    firewall_rules: {
      default_incoming: 'deny',
      default_outgoing: 'allow',
      allowed_services: ['http', 'https', 'dns']
    }
  };
};
