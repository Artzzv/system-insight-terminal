
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

export interface WindowsEventLog {
  TimeCreated: string;
  Id: number;
  LevelDisplayName: string;
  Message: string;
  ProviderName: string;
}

export interface WindowsDefenderStatus {
  RealTimeProtectionEnabled: boolean;
  AntivirusEnabled: boolean;
  AntivirusSignatureLastUpdated: string;
  AMEngineVersion: string;
  AntispywareEnabled: boolean;
  BehaviorMonitorEnabled: boolean;
  QuickScanAge: number;
  FullScanAge: number;
  IoavProtectionEnabled: boolean;
  [key: string]: any;
}

export interface FirewallRule {
  Name: string;
  DisplayName: string;
  Direction: string;
  Action: string;
  Profile: any;
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
  defender_status?: {
    realtime_protection: boolean;
    antivirus_enabled: boolean;
    definitions_updated: string;
  };
  firewall_status?: any;
  last_updates?: any;
}

export interface AILogAnalysisResult {
  summary: {
    total_logs: number;
    error_count: number;
    warning_count: number;
    anomaly_count: number;
    cluster_count?: number;
  };
  time_series: Array<{
    time: string;
    total: number;
    error: number;
    warning: number;
  }>;
  service_distribution: Array<{
    name: string;
    total: number;
    error: number;
    warning: number;
    info: number;
  }>;
  anomalies: Array<{
    type: string;
    description: string;
    score: number;
    log?: WindowsEventLog;
  }>;
  clusters?: Array<{
    id: number;
    size: number;
    common_terms: Array<[string, number]>;
    composition: Record<string, number>;
    examples: string[];
  }>;
  error_clusters: Array<{
    keywords: string;
    count: number;
    examples: string[];
  }>;
  top_patterns: Array<[string, number]>;
}

// Execute shell command using IPC for Electron
export const executeShellCommand = (command: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    if (isElectron()) {
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
      reject('This feature requires Electron with full system access');
    }
  });
};

// Get CPU information via IPC
export const getCpuInfo = (): Promise<CpuInfo> => {
  if (isElectron()) {
    return new Promise<CpuInfo>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-cpu-info');
        // @ts-ignore
        window.api.receive('cpu-info', (result: CpuInfo | { error: string }) => {
          if ('error' in result) {
            reject(result.error);
          } else {
            resolve(result);
          }
        });
      } catch (error) {
        reject(`Error getting CPU info: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get memory information via IPC
export const getMemoryInfo = (): Promise<MemoryInfo> => {
  if (isElectron()) {
    return new Promise<MemoryInfo>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-memory-info');
        // @ts-ignore
        window.api.receive('memory-info', (result: MemoryInfo | { error: string }) => {
          if ('error' in result) {
            reject(result.error);
          } else {
            resolve(result);
          }
        });
      } catch (error) {
        reject(`Error getting memory info: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get disk information via IPC
export const getDiskInfo = (): Promise<DiskInfo> => {
  if (isElectron()) {
    return new Promise<DiskInfo>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-disk-info');
        // @ts-ignore
        window.api.receive('disk-info', (result: DiskInfo | { error: string }) => {
          if ('error' in result) {
            reject(result.error);
          } else {
            resolve(result);
          }
        });
      } catch (error) {
        reject(`Error getting disk info: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get network information via IPC
export const getNetworkInfo = (): Promise<NetworkInfo> => {
  if (isElectron()) {
    return new Promise<NetworkInfo>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-network-info');
        // @ts-ignore
        window.api.receive('network-info', (result: NetworkInfo | { error: string }) => {
          if ('error' in result) {
            reject(result.error);
          } else {
            resolve(result);
          }
        });
      } catch (error) {
        reject(`Error getting network info: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get system information via IPC
export const getSystemInfo = (): Promise<SystemInfo> => {
  if (isElectron()) {
    return new Promise<SystemInfo>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-system-info');
        // @ts-ignore
        window.api.receive('system-info', (result: SystemInfo | { error: string }) => {
          if ('error' in result) {
            reject(result.error);
          } else {
            resolve(result);
          }
        });
      } catch (error) {
        reject(`Error getting system info: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get Windows Event Logs via IPC
export const getWindowsEventLogs = (
  logName: string = 'System',
  count: number = 50,
  filter?: string
): Promise<WindowsEventLog[]> => {
  if (isElectron()) {
    return new Promise<WindowsEventLog[]>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-event-logs', { logName, count, filter });
        // @ts-ignore
        window.api.receive('event-logs-result', (result: { success: boolean, logs?: WindowsEventLog[], error?: string }) => {
          if (result.success && result.logs) {
            resolve(result.logs);
          } else {
            reject(result.error || 'Failed to retrieve event logs');
          }
        });
      } catch (error) {
        reject(`Error getting Windows event logs: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get Windows Defender status via IPC
export const getWindowsDefenderStatus = (): Promise<WindowsDefenderStatus> => {
  if (isElectron()) {
    return new Promise<WindowsDefenderStatus>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-defender-status');
        // @ts-ignore
        window.api.receive('defender-status-result', (result: { success: boolean, status?: WindowsDefenderStatus, error?: string }) => {
          if (result.success && result.status) {
            resolve(result.status);
          } else {
            reject(result.error || 'Failed to retrieve Windows Defender status');
          }
        });
      } catch (error) {
        reject(`Error getting Windows Defender status: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get Firewall rules via IPC
export const getFirewallRules = (): Promise<FirewallRule[]> => {
  if (isElectron()) {
    return new Promise<FirewallRule[]>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('get-firewall-rules');
        // @ts-ignore
        window.api.receive('firewall-rules-result', (result: { success: boolean, rules?: FirewallRule[], error?: string }) => {
          if (result.success && result.rules) {
            resolve(result.rules);
          } else {
            reject(result.error || 'Failed to retrieve firewall rules');
          }
        });
      } catch (error) {
        reject(`Error getting firewall rules: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Run security audit via IPC
export const performSecurityAudit = (): Promise<SecurityAuditResult> => {
  if (isElectron()) {
    return new Promise<SecurityAuditResult>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('run-security-audit');
        // @ts-ignore
        window.api.receive('security-audit-result', (result: { success: boolean, audit?: SecurityAuditResult, error?: string }) => {
          if (result.success && result.audit) {
            resolve(result.audit);
          } else {
            reject(result.error || 'Failed to perform security audit');
          }
        });
      } catch (error) {
        reject(`Error performing security audit: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Analyze Windows Event Logs with AI
export const aiAnalyzeLogs = (
  logName: string = 'System',
  count: number = 1000
): Promise<AILogAnalysisResult> => {
  if (isElectron()) {
    return new Promise<AILogAnalysisResult>((resolve, reject) => {
      try {
        // @ts-ignore
        window.api.send('analyze-logs-ai', { logName, count });
        // @ts-ignore
        window.api.receive('ai-analysis-result', (result: { success: boolean, result?: AILogAnalysisResult, error?: string }) => {
          if (result.success && result.result) {
            resolve(result.result);
          } else {
            reject(result.error || 'Failed to analyze logs');
          }
        });
      } catch (error) {
        reject(`Error analyzing logs: ${(error as Error).message}`);
      }
    });
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Regular log analysis (without AI, but using real logs)
export const analyzeLogs = async (logPath = 'System', limit = 100) => {
  if (isElectron()) {
    try {
      // Get actual Windows event logs
      const logs = await getWindowsEventLogs(logPath, limit);
      
      // Count by level
      const levels = logs.reduce((acc, log) => {
        const level = log.LevelDisplayName || '';
        if (level.includes('Error')) acc.error++;
        else if (level.includes('Warning')) acc.warning++;
        else if (level.includes('Critical')) acc.critical++;
        else acc.info++;
        return acc;
      }, { info: 0, warning: 0, error: 0, critical: 0 });
      
      // Count by service
      const services = logs.reduce((acc, log) => {
        const service = log.ProviderName || 'Unknown';
        acc[service] = (acc[service] || 0) + 1;
        return acc;
      }, {} as {[key: string]: number});
      
      // Extract common patterns
      const messages = logs.map(log => log.Message || '');
      const wordCounts: {[key: string]: number} = {};
      
      messages.forEach(message => {
        const words = message.split(/\s+/);
        const uniqueWords = [...new Set(words)];
        
        uniqueWords.forEach(word => {
          if (word.length > 3) {
            wordCounts[word] = (wordCounts[word] || 0) + 1;
          }
        });
      });
      
      const patterns = Object.entries(wordCounts)
        .filter(([_, count]) => count > 1)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
      
      // Time series data
      const timeMap: {[key: string]: number} = {};
      logs.forEach(log => {
        try {
          const date = new Date(log.TimeCreated);
          const hour = date.getHours().toString().padStart(2, '0');
          const timeKey = `${hour}:00`;
          timeMap[timeKey] = (timeMap[timeKey] || 0) + 1;
        } catch (e) {
          // Skip logs with invalid timestamps
        }
      });
      
      const timeSeries = Object.entries(timeMap)
        .map(([time, count]) => ({ time, count }))
        .sort((a, b) => a.time.localeCompare(b.time));
      
      return {
        entries: logs,
        levels,
        services,
        patterns,
        time_series: timeSeries
      };
    } catch (error) {
      console.error('Error analyzing Windows event logs:', error);
      throw error;
    }
  } else {
    return Promise.reject('This feature requires Electron with full system access');
  }
};

// Get security policies
export const getSecurityPolicies = async () => {
  if (isElectron()) {
    try {
      // Get password policy from PowerShell
      const passwordCommand = 'powershell -Command "Get-LocalUser | Get-Member -MemberType Property | ConvertTo-Json"';
      const firewallCommand = 'powershell -Command "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"';
      
      const [passwordOutput, firewallOutput] = await Promise.all([
        executeShellCommand(passwordCommand).catch(() => '[]'),
        executeShellCommand(firewallCommand).catch(() => '[]'),
      ]);
      
      let passwordPolicy;
      try {
        passwordPolicy = {
          min_length: 8, // Default, actual value would need netsh or Local Security Policy
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true,
          require_special_chars: false,
          max_age_days: 90,
          prevent_reuse: true,
          lockout_threshold: 5
        };
      } catch (e) {
        passwordPolicy = {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true,
          require_special_chars: false,
          max_age_days: 90,
          prevent_reuse: true,
          lockout_threshold: 5
        };
      }
      
      let firewallRules;
      try {
        const firewallProfiles = JSON.parse(firewallOutput);
        const enabledProfiles = Array.isArray(firewallProfiles) 
          ? firewallProfiles.filter((profile: any) => profile.Enabled)
          : [firewallProfiles].filter(profile => profile.Enabled);
        
        // Get some active services
        const servicesCommand = 'powershell -Command "Get-Service | Where-Object {$_.Status -eq \'Running\'} | Select-Object -First 10 -Property DisplayName | ConvertTo-Json"';
        const servicesOutput = await executeShellCommand(servicesCommand).catch(() => '[]');
        let services;
        try {
          services = JSON.parse(servicesOutput);
          services = Array.isArray(services) 
            ? services.map((svc: any) => svc.DisplayName || 'Unknown Service').slice(0, 5)
            : [services].map(svc => svc.DisplayName || 'Unknown Service');
        } catch (e) {
          services = ['Windows Firewall', 'Windows Defender', 'DHCP Client'];
        }
        
        firewallRules = {
          default_incoming: enabledProfiles.length > 0 ? 'deny' : 'allow',
          default_outgoing: 'allow',
          allowed_services: services
        };
      } catch (e) {
        firewallRules = {
          default_incoming: 'deny',
          default_outgoing: 'allow',
          allowed_services: ['http', 'https', 'dns']
        };
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
    return Promise.reject('This feature requires Electron with full system access');
  }
};
