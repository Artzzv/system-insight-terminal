
import React from 'react';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line } from 'recharts';
import { 
  getCpuInfo,
  getMemoryInfo,
  getDiskInfo,
  getNetworkInfo,
  getSystemInfo,
  performSecurityAudit,
  analyzeLogs,
  aiAnalyzeLogs,
  getSecurityPolicies,
  executeShellCommand,
  getWindowsEventLogs,
  getWindowsDefenderStatus,
  getFirewallRules
} from './systemInfo';
import { isElectron } from './isElectron';

interface CommandResult {
  content: React.ReactNode;
  type: 'standard' | 'success' | 'error' | 'warning' | 'info' | 'jsx';
}

// Colors for charts
const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D', '#FFC658'];
const ERROR_COLOR = '#FF4842';
const WARNING_COLOR = '#FFC107';
const INFO_COLOR = '#2196F3';
const SUCCESS_COLOR = '#4CAF50';

// Help information
const helpInfo = `
Available commands:

Basic Commands:
  help                Display this help information
  clear               Clear the terminal screen
  exit                Exit the terminal session

System Commands:
  system-health       Display real-time system health metrics
  ps                  List running processes
  top                 Display system resource usage
  df                  Show disk space usage
  free                Display memory usage

Network Commands:
  network-check       Check network interfaces and connectivity
  ping <host>         Ping a host
  ifconfig            Display network interfaces
  netstat             Display network connections
  traceroute <host>   Trace the route to a host

Security Commands:
  audit               Run a real-time security audit
  show-policies       Display actual security policies
  show-defender       Show Windows Defender status
  show-firewall       Show Windows Firewall rules

Log Analysis:
  analyze-logs [path] Analyze system logs (default: System)
  analyze-logs Application   Analyze application logs
  analyze-logs Security      Analyze security logs
  analyze-logs <name>        Analyze specific Windows event log
  
  event-logs [log] [count]   Show raw Windows event logs
  ai-analyze-logs [log]      AI-powered log analysis with anomaly detection

File Operations:
  ls [dir]            List directory contents
  cd <dir>            Change directory
  pwd                 Print working directory
  cat <file>          Display file content
  find <pattern>      Search for files

Type any command to execute it.
`;

export async function executeCommand(command: string): Promise<CommandResult> {
  const parts = command.trim().split(' ');
  const mainCommand = parts[0].toLowerCase();
  const args = parts.slice(1);
  
  try {
    switch (mainCommand) {
      case 'help':
        return { content: helpInfo, type: 'info' };
      
      case 'network-check':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          const networkData = await getNetworkInfo();
          
          return { 
            content: (
              <div className="space-y-2">
                <p>Performing real-time network check...</p>
                <div className="space-y-4 mt-2">
                  <p className="font-semibold">Network Interfaces:</p>
                  <table className="min-w-full">
                    <thead>
                      <tr>
                        <th className="text-left pr-4">Interface</th>
                        <th className="text-left pr-4">Status</th>
                        <th className="text-left pr-4">IP Address</th>
                        <th className="text-left">MAC Address</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(networkData.interfaces).map(([name, info]: [string, any]) => (
                        <tr key={name}>
                          <td className="pr-4">{name}</td>
                          <td className="pr-4 text-terminal-success">connected</td>
                          <td className="pr-4">{info.ip}</td>
                          <td>{info.mac}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  
                  <p className="font-semibold mt-4">Network Statistics:</p>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span>Bytes Sent:</span>
                      <span>{networkData.io_counters.bytes_sent.toLocaleString()} bytes</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Bytes Received:</span>
                      <span>{networkData.io_counters.bytes_received.toLocaleString()} bytes</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Packets Sent:</span>
                      <span>{networkData.io_counters.packets_sent.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Packets Received:</span>
                      <span>{networkData.io_counters.packets_received.toLocaleString()}</span>
                    </div>
                  </div>
                  
                  <p className="font-semibold mt-4">Active Connections:</p>
                  <div className="max-h-40 overflow-y-auto">
                    <table className="min-w-full">
                      <thead>
                        <tr>
                          <th className="text-left pr-4">Protocol</th>
                          <th className="text-left pr-4">Local Address</th>
                          <th className="text-left pr-4">Remote Address</th>
                          <th className="text-left">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {networkData.connections.slice(0, 10).map((conn: any, index: number) => (
                          <tr key={index}>
                            <td className="pr-4">{conn.type}</td>
                            <td className="pr-4">{conn.local_address || '-'}</td>
                            <td className="pr-4">{conn.remote_address || '-'}</td>
                            <td>{conn.status}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {networkData.connections.length > 10 && (
                      <p className="text-xs text-terminal-info mt-2">
                        Showing 10 of {networkData.connections.length} connections
                      </p>
                    )}
                  </div>
                  
                  <p className="text-terminal-success font-semibold mt-2">
                    Network check completed successfully.
                  </p>
                </div>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error retrieving network information: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'system-health':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Get real system data using our Node.js functions
          const cpuData = await getCpuInfo();
          const memoryData = await getMemoryInfo();
          const diskData = await getDiskInfo();
          const systemData = await getSystemInfo();
          
          // Calculate uptime
          const bootTime = new Date(systemData.boot_time);
          const now = new Date();
          const uptimeMs = now.getTime() - bootTime.getTime();
          const uptimeDays = Math.floor(uptimeMs / (1000 * 60 * 60 * 24));
          const uptimeHours = Math.floor((uptimeMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
          const uptimeMinutes = Math.floor((uptimeMs % (1000 * 60 * 60)) / (1000 * 60));
          const uptime = `${uptimeDays} days, ${uptimeHours} hours, ${uptimeMinutes} minutes`;
          
          // Format disk and memory sizes to GB
          const formatBytes = (bytes: number, decimals = 2) => {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
          };
          
          // Create chart data for CPU usage
          const cpuChartData = cpuData.cpu_usage_per_core.map((usage: number, index: number) => ({
            name: `Core ${index + 1}`,
            usage
          }));
          
          return {
            content: (
              <div className="space-y-4">
                <p>Real-time System Health Report for {systemData.hostname}:</p>
                
                <div className="space-y-2">
                  <p className="font-semibold">CPU Usage:</p>
                  <div className="flex items-center space-x-2">
                    <div className="flex-1">
                      <Progress value={cpuData.total_cpu_usage} className="h-2" />
                    </div>
                    <span>{cpuData.total_cpu_usage.toFixed(1)}%</span>
                  </div>
                  <div className="h-40 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={cpuChartData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="name" />
                        <YAxis domain={[0, 100]} />
                        <Tooltip />
                        <Bar dataKey="usage" fill="#8884d8" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>Physical Cores: {cpuData.physical_cores}</div>
                    <div>Logical Cores: {cpuData.total_cores}</div>
                    {cpuData.cpu_frequency.current && (
                      <div>CPU Frequency: {cpuData.cpu_frequency.current.toFixed(0)} MHz</div>
                    )}
                    <div>CPU Model: {cpuData.model}</div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <p className="font-semibold">Memory:</p>
                  <div className="flex items-center space-x-2">
                    <div className="flex-1">
                      <Progress value={memoryData.virtual_memory.percentage} className="h-2" />
                    </div>
                    <span>{memoryData.virtual_memory.percentage.toFixed(1)}%</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-sm">
                    <div>Total: {formatBytes(memoryData.virtual_memory.total)}</div>
                    <div>Used: {formatBytes(memoryData.virtual_memory.used)}</div>
                    <div>Available: {formatBytes(memoryData.virtual_memory.available)}</div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <p className="font-semibold">Disk Space:</p>
                  <div className="grid gap-2">
                    {diskData.partitions.map((partition: any, index: number) => (
                      <div key={index} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span>{partition.mountpoint} ({partition.device})</span>
                          <span>{partition.percentage.toFixed(1)}% used</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className="flex-1">
                            <Progress value={partition.percentage} className="h-2" />
                          </div>
                        </div>
                        <div className="text-xs grid grid-cols-3 gap-1">
                          <div>Total: {formatBytes(partition.total_size)}</div>
                          <div>Used: {formatBytes(partition.used)}</div>
                          <div>Free: {formatBytes(partition.free)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4 text-sm mt-2">
                  <div>
                    <span className="font-semibold">System Uptime:</span> {uptime}
                  </div>
                  <div>
                    <span className="font-semibold">Platform:</span> {systemData.platform}
                  </div>
                </div>
                
                <p className="text-terminal-success font-semibold mt-2">
                  System health check completed. {memoryData.virtual_memory.percentage > 90 || cpuData.total_cpu_usage > 90 ? "Warning: High resource usage detected." : "All systems normal."}
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error retrieving system health information: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'audit':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          const auditData = await performSecurityAudit();
          
          // Create pie chart data for issues by severity
          const severityData = [
            { name: 'High', value: auditData.issues_by_severity.high, color: ERROR_COLOR },
            { name: 'Medium', value: auditData.issues_by_severity.medium, color: WARNING_COLOR },
            { name: 'Low', value: auditData.issues_by_severity.low, color: INFO_COLOR }
          ].filter(item => item.value > 0);
          
          return {
            content: (
              <div className="space-y-4">
                <p>Running real-time security audit for {auditData.hostname}...</p>
                
                {severityData.length > 0 && (
                  <div className="h-40 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityData}
                          cx="50%"
                          cy="50%"
                          outerRadius={60}
                          dataKey="value"
                          label={({ name, value }) => `${name}: ${value}`}
                        >
                          {severityData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
                
                {auditData.issues.length > 0 && (
                  <>
                    <Separator />
                    
                    <div>
                      <p className="font-semibold">Issues found:</p>
                      <ul className="list-disc list-inside space-y-1 mt-1">
                        {auditData.issues.map((issue: any, index: number) => (
                          <li key={index} className={
                            issue.severity === 'high' ? 'text-terminal-error' : 
                            issue.severity === 'medium' ? 'text-terminal-warning' : 
                            'text-terminal-info'
                          }>
                            {issue.issue}
                          </li>
                        ))}
                      </ul>
                    </div>
                    
                    <div>
                      <p className="font-semibold">Recommendations:</p>
                      <ul className="list-disc list-inside space-y-1 mt-1">
                        {auditData.issues.map((issue: any, index: number) => (
                          <li key={index}>
                            {issue.recommendation}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </>
                )}
                
                {auditData.defender_status && (
                  <div className="space-y-2">
                    <p className="font-semibold">Windows Defender Status:</p>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="flex items-center">
                        <span className={auditData.defender_status.realtime_protection ? 'text-terminal-success' : 'text-terminal-error'}>
                          Real-time Protection: {auditData.defender_status.realtime_protection ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                      <div className="flex items-center">
                        <span className={auditData.defender_status.antivirus_enabled ? 'text-terminal-success' : 'text-terminal-error'}>
                          Antivirus: {auditData.defender_status.antivirus_enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                      <div className="col-span-2">
                        <span>Definitions Last Updated: {auditData.defender_status.definitions_updated}</span>
                      </div>
                    </div>
                  </div>
                )}
                
                {auditData.firewall_status && (
                  <div className="space-y-2">
                    <p className="font-semibold">Firewall Status:</p>
                    <div className="max-h-24 overflow-y-auto">
                      <table className="min-w-full">
                        <thead>
                          <tr>
                            <th className="text-left pr-4">Profile</th>
                            <th className="text-left">Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Array.isArray(auditData.firewall_status) ? (
                            auditData.firewall_status.map((profile: any, index: number) => (
                              <tr key={index}>
                                <td className="pr-4">{profile.Name}</td>
                                <td className={profile.Enabled ? 'text-terminal-success' : 'text-terminal-error'}>
                                  {profile.Enabled ? 'Enabled' : 'Disabled'}
                                </td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td className="pr-4">{auditData.firewall_status.Name}</td>
                              <td className={auditData.firewall_status.Enabled ? 'text-terminal-success' : 'text-terminal-error'}>
                                {auditData.firewall_status.Enabled ? 'Enabled' : 'Disabled'}
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
                
                {auditData.issues.length === 0 && (
                  <p className="text-terminal-success">
                    No security issues found. Your system is properly configured.
                  </p>
                )}
                
                <p className={
                  auditData.issues_by_severity.high > 0 ? 'text-terminal-error font-semibold mt-2' :
                  auditData.issues_by_severity.medium > 0 ? 'text-terminal-warning font-semibold mt-2' :
                  'text-terminal-success font-semibold mt-2'
                }>
                  Audit completed with {auditData.issues_by_severity.high} critical, {auditData.issues_by_severity.medium} warning, and {auditData.issues_by_severity.low} informational issues.
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error performing security audit: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'show-policies':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          const policiesData = await getSecurityPolicies();
          
          return {
            content: (
              <div className="space-y-4">
                <p>Real Security Policies:</p>
                
                {/* Password Policy */}
                <div className="space-y-2">
                  <p className="font-semibold">Password Policy:</p>
                  <table className="min-w-full">
                    <tbody>
                      <tr>
                        <td className="pr-4">Minimum Length:</td>
                        <td>{policiesData.password_policy.min_length ?? 'Not configured'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Require Uppercase:</td>
                        <td>{policiesData.password_policy.require_uppercase ? 'Yes' : 'No'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Require Lowercase:</td>
                        <td>{policiesData.password_policy.require_lowercase ? 'Yes' : 'No'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Require Numbers:</td>
                        <td>{policiesData.password_policy.require_numbers ? 'Yes' : 'No'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Require Special Characters:</td>
                        <td>{policiesData.password_policy.require_special_chars ? 'Yes' : 'No'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Maximum Age (days):</td>
                        <td>{policiesData.password_policy.max_age_days ?? 'Not configured'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Prevent Password Reuse:</td>
                        <td>{policiesData.password_policy.prevent_reuse ? 'Yes' : 'No'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Account Lockout Threshold:</td>
                        <td>{policiesData.password_policy.lockout_threshold ?? 'Not configured'}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                
                {/* Firewall Rules */}
                <div className="space-y-2">
                  <p className="font-semibold">Firewall Rules:</p>
                  <table className="min-w-full">
                    <tbody>
                      <tr>
                        <td className="pr-4">Default Incoming Policy:</td>
                        <td className={policiesData.firewall_rules.default_incoming === 'deny' ? 'text-terminal-success' : 'text-terminal-warning'}>
                          {policiesData.firewall_rules.default_incoming ?? 'Not configured'}
                        </td>
                      </tr>
                      <tr>
                        <td className="pr-4">Default Outgoing Policy:</td>
                        <td>{policiesData.firewall_rules.default_outgoing ?? 'Not configured'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Allowed Services:</td>
                        <td>{policiesData.firewall_rules.allowed_services.length > 0 ? 
                          policiesData.firewall_rules.allowed_services.join(', ') : 
                          'None detected'}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                
                <p className="mt-2">
                  For detailed firewall information, use: <span className="text-terminal-command">show-firewall</span>
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error retrieving security policies: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'show-defender':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          const defenderStatus = await getWindowsDefenderStatus();
          
          return {
            content: (
              <div className="space-y-4">
                <p className="font-semibold">Windows Defender Status:</p>
                
                <div className="space-y-2">
                  <table className="min-w-full">
                    <tbody>
                      <tr>
                        <td className="pr-4">Real-time Protection:</td>
                        <td className={defenderStatus.RealTimeProtectionEnabled ? 'text-terminal-success' : 'text-terminal-error'}>
                          {defenderStatus.RealTimeProtectionEnabled ? 'Enabled' : 'Disabled'}
                        </td>
                      </tr>
                      <tr>
                        <td className="pr-4">Antivirus:</td>
                        <td className={defenderStatus.AntivirusEnabled ? 'text-terminal-success' : 'text-terminal-error'}>
                          {defenderStatus.AntivirusEnabled ? 'Enabled' : 'Disabled'}
                        </td>
                      </tr>
                      <tr>
                        <td className="pr-4">Antispyware:</td>
                        <td className={defenderStatus.AntispywareEnabled ? 'text-terminal-success' : 'text-terminal-error'}>
                          {defenderStatus.AntispywareEnabled ? 'Enabled' : 'Disabled'}
                        </td>
                      </tr>
                      <tr>
                        <td className="pr-4">Behavior Monitoring:</td>
                        <td className={defenderStatus.BehaviorMonitorEnabled ? 'text-terminal-success' : 'text-terminal-error'}>
                          {defenderStatus.BehaviorMonitorEnabled ? 'Enabled' : 'Disabled'}
                        </td>
                      </tr>
                      <tr>
                        <td className="pr-4">IOAV Protection:</td>
                        <td className={defenderStatus.IoavProtectionEnabled ? 'text-terminal-success' : 'text-terminal-error'}>
                          {defenderStatus.IoavProtectionEnabled ? 'Enabled' : 'Disabled'}
                        </td>
                      </tr>
                      <tr>
                        <td className="pr-4">Engine Version:</td>
                        <td>{defenderStatus.AMEngineVersion || 'Unknown'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Signatures Last Updated:</td>
                        <td>{defenderStatus.AntivirusSignatureLastUpdated || 'Unknown'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Days Since Full Scan:</td>
                        <td>{defenderStatus.FullScanAge !== undefined ? defenderStatus.FullScanAge : 'Unknown'}</td>
                      </tr>
                      <tr>
                        <td className="pr-4">Days Since Quick Scan:</td>
                        <td>{defenderStatus.QuickScanAge !== undefined ? defenderStatus.QuickScanAge : 'Unknown'}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                
                <p className="mt-2">
                  For a full security assessment, run: <span className="text-terminal-command">audit</span>
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error retrieving Windows Defender status: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'show-firewall':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          const firewallRules = await getFirewallRules();
          
          return {
            content: (
              <div className="space-y-4">
                <p className="font-semibold">Windows Firewall Rules:</p>
                
                <div className="space-y-2">
                  <div className="max-h-60 overflow-y-auto">
                    <table className="min-w-full">
                      <thead>
                        <tr>
                          <th className="text-left pr-4">Name</th>
                          <th className="text-left pr-4">Direction</th>
                          <th className="text-left pr-4">Action</th>
                          <th className="text-left">Profile</th>
                        </tr>
                      </thead>
                      <tbody>
                        {firewallRules.slice(0, 50).map((rule: any, index: number) => (
                          <tr key={index}>
                            <td className="pr-4">{rule.DisplayName || rule.Name}</td>
                            <td className="pr-4">{rule.Direction}</td>
                            <td className="pr-4" className={rule.Action === 'Allow' ? 'text-terminal-success' : 'text-terminal-error'}>
                              {rule.Action}
                            </td>
                            <td>{
                              typeof rule.Profile === 'object' 
                                ? Object.keys(rule.Profile).filter(key => rule.Profile[key]).join(', ')
                                : rule.Profile
                            }</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  
                  {firewallRules.length > 50 && (
                    <p className="text-xs text-terminal-info">
                      Showing 50 of {firewallRules.length} rules
                    </p>
                  )}
                </div>
                
                <p className="mt-2">
                  For a complete security assessment, run: <span className="text-terminal-command">audit</span>
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error retrieving firewall rules: ${(error as Error).message}`,
            type: 'error' 
          };
        }
        
      case 'event-logs':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Determine which log to query
          const logName = args[0] || 'System';
          const count = args[1] ? parseInt(args[1], 10) : 20;
          
          const logs = await getWindowsEventLogs(logName, count);
          
          return {
            content: (
              <div className="space-y-4">
                <p className="font-semibold">Windows Event Logs - {logName}:</p>
                
                <div className="space-y-2">
                  <div className="max-h-80 overflow-y-auto">
                    <table className="min-w-full">
                      <thead>
                        <tr>
                          <th className="text-left pr-4">Time</th>
                          <th className="text-left pr-4">ID</th>
                          <th className="text-left pr-4">Level</th>
                          <th className="text-left pr-4">Provider</th>
                          <th className="text-left">Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {logs.map((log: any, index: number) => (
                          <tr key={index}>
                            <td className="pr-4 text-xs">{log.TimeCreated}</td>
                            <td className="pr-4">{log.Id}</td>
                            <td className={`pr-4 ${
                              log.LevelDisplayName === 'Error' || log.LevelDisplayName === 'Critical' ? 'text-terminal-error' : 
                              log.LevelDisplayName === 'Warning' ? 'text-terminal-warning' : 'text-terminal-info'
                            }`}>
                              {log.LevelDisplayName}
                            </td>
                            <td className="pr-4">{log.ProviderName}</td>
                            <td className="truncate max-w-xs">{log.Message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  
                  <p className="text-xs text-terminal-info">
                    Showing {logs.length} events from the {logName} log
                  </p>
                </div>
                
                <p className="mt-2">
                  For AI-powered log analysis, use: <span className="text-terminal-command">ai-analyze-logs {logName}</span>
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error retrieving Windows event logs: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'analyze-logs':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Determine which log path to analyze
          let logPath = 'System'; // Default
          if (args.length > 0) {
            logPath = args[0];
          }
          
          const logsData = await analyzeLogs(logPath);
          
          // Create chart data for log levels
          const levelData = [
            { name: 'Info', value: logsData.levels.info, color: INFO_COLOR },
            { name: 'Warning', value: logsData.levels.warning, color: WARNING_COLOR },
            { name: 'Error', value: logsData.levels.error, color: ERROR_COLOR },
            { name: 'Critical', value: logsData.levels.critical, color: '#9c27b0' }
          ].filter(item => item.value > 0);
          
          return {
            content: (
              <div className="space-y-4">
                <p>Windows Event Log Analysis for {logPath}:</p>
                
                {/* Log level distribution chart */}
                {levelData.length > 0 && (
                  <div className="h-40 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={levelData}
                          cx="50%"
                          cy="50%"
                          outerRadius={60}
                          dataKey="value"
                          label={({ name, value }) => `${name}: ${value}`}
                        >
                          {levelData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
                
                {/* Most active services */}
                {Object.keys(logsData.services).length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Most Active Providers:</p>
                    <div className="max-h-24 overflow-y-auto">
                      <table className="min-w-full">
                        <thead>
                          <tr>
                            <th className="text-left pr-4">Provider</th>
                            <th className="text-left">Count</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(logsData.services)
                            .sort((a: any, b: any) => b[1] - a[1])
                            .slice(0, 5)
                            .map(([service, count]: [string, any], index: number) => (
                              <tr key={index}>
                                <td className="pr-4">{service}</td>
                                <td>{count}</td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
                
                {/* Time based pattern */}
                {logsData.time_series && logsData.time_series.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Event Frequency:</p>
                    <div className="h-40 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={logsData.time_series}>
                          <XAxis dataKey="time" />
                          <YAxis />
                          <CartesianGrid strokeDasharray="3 3" />
                          <Tooltip />
                          <Line type="monotone" dataKey="count" stroke="#8884d8" />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
                
                {/* Log entries table */}
                <div className="space-y-2">
                  <p className="font-semibold">Recent Log Entries:</p>
                  <div className="max-h-60 overflow-y-auto">
                    <table className="min-w-full">
                      <thead>
                        <tr>
                          <th className="text-left pr-4">Timestamp</th>
                          <th className="text-left pr-4">Level</th>
                          <th className="text-left pr-4">Provider</th>
                          <th className="text-left">Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {logsData.entries.slice(0, 10).map((log: any, index: number) => (
                          <tr key={index}>
                            <td className="pr-4 text-xs">{log.TimeCreated}</td>
                            <td className={`pr-4 ${
                              log.LevelDisplayName === 'Error' || log.LevelDisplayName === 'Critical' ? 'text-terminal-error' : 
                              log.LevelDisplayName === 'Warning' ? 'text-terminal-warning' : 'text-terminal-info'
                            }`}>
                              {log.LevelDisplayName}
                            </td>
                            <td className="pr-4">{log.ProviderName}</td>
                            <td className="truncate max-w-xs">{log.Message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                
                {/* Most common patterns */}
                {logsData.patterns && logsData.patterns.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Common Patterns:</p>
                    <ul className="list-disc list-inside">
                      {logsData.patterns.map((pattern: any, index: number) => (
                        <li key={index}>{pattern[0]} ({pattern[1]} occurrences)</li>
                      ))}
                    </ul>
                  </div>
                )}
                
                <p className="mt-2">
                  For advanced AI-powered analysis, use: <span className="text-terminal-command">ai-analyze-logs {logPath}</span>
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error analyzing Windows event logs: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'ai-analyze-logs':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Determine which log path to analyze
          let logPath = 'System'; // Default
          if (args.length > 0) {
            logPath = args[0];
          }
          
          const aiAnalysisData = await aiAnalyzeLogs(logPath);
          
          // Prepare data for visualizations
          const timeSeriesData = aiAnalysisData.time_series || [];
          const serviceData = aiAnalysisData.service_distribution || [];
          
          // Error clusters
          const errorClusters = aiAnalysisData.error_clusters || [];
          
          return {
            content: (
              <div className="space-y-4">
                <p>AI-Powered Log Analysis for {logPath}:</p>
                
                {/* Summary stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-secondary p-4 rounded">
                    <div className="text-xs text-muted-foreground">Total Logs</div>
                    <div className="text-2xl font-bold">{aiAnalysisData.summary.total_logs}</div>
                  </div>
                  <div className="bg-secondary p-4 rounded">
                    <div className="text-xs text-muted-foreground">Errors</div>
                    <div className="text-2xl font-bold text-terminal-error">{aiAnalysisData.summary.error_count}</div>
                  </div>
                  <div className="bg-secondary p-4 rounded">
                    <div className="text-xs text-muted-foreground">Warnings</div>
                    <div className="text-2xl font-bold text-terminal-warning">{aiAnalysisData.summary.warning_count}</div>
                  </div>
                  <div className="bg-secondary p-4 rounded">
                    <div className="text-xs text-muted-foreground">Anomalies</div>
                    <div className="text-2xl font-bold text-terminal-info">{aiAnalysisData.summary.anomaly_count}</div>
                  </div>
                </div>
                
                {/* Time series chart */}
                {timeSeriesData.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Activity Over Time:</p>
                    <div className="h-48 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={timeSeriesData}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="time" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Line type="monotone" dataKey="total" stroke="#8884d8" />
                          <Line type="monotone" dataKey="error" stroke={ERROR_COLOR} />
                          <Line type="monotone" dataKey="warning" stroke={WARNING_COLOR} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
                
                {/* Service distribution */}
                {serviceData.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Service Activity:</p>
                    <div className="h-48 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={serviceData.slice(0, 7)}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="error" fill={ERROR_COLOR} stackId="a" />
                          <Bar dataKey="warning" fill={WARNING_COLOR} stackId="a" />
                          <Bar dataKey="info" fill={INFO_COLOR} stackId="a" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
                
                {/* Clusters - AI Grouping */}
                {aiAnalysisData.clusters && aiAnalysisData.clusters.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">AI-Detected Log Clusters:</p>
                    <div className="max-h-60 overflow-y-auto space-y-3">
                      {aiAnalysisData.clusters.map((cluster: any, index: number) => (
                        <div key={index} className="p-3 border border-border rounded-md">
                          <div className="flex justify-between items-start">
                            <div className="font-semibold">Cluster {index + 1}</div>
                            <div className="bg-secondary px-2 py-1 rounded text-xs">{cluster.size} logs</div>
                          </div>
                          
                          {cluster.common_terms && cluster.common_terms.length > 0 && (
                            <div className="mt-2">
                              <span className="text-xs text-muted-foreground">Common Terms: </span>
                              <span className="text-xs">
                                {cluster.common_terms.slice(0, 3).map(([term, count]: [string, number]) => 
                                  `${term} (${count})`
                                ).join(', ')}
                              </span>
                            </div>
                          )}
                          
                          {cluster.examples && cluster.examples.length > 0 && (
                            <div className="mt-1 text-xs text-muted-foreground">
                              <div>Example: {cluster.examples[0]}</div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Error clusters */}
                {errorClusters.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Error Patterns:</p>
                    <div className="max-h-60 overflow-y-auto space-y-3">
                      {errorClusters.map((cluster: any, index: number) => (
                        <div key={index} className="p-3 border border-border rounded-md">
                          <div className="flex justify-between items-start">
                            <div className="font-semibold text-terminal-error">{cluster.keywords}</div>
                            <div className="bg-secondary px-2 py-1 rounded text-xs">{cluster.count} occurrences</div>
                          </div>
                          <div className="mt-2 text-xs text-muted-foreground">
                            <div className="font-semibold">Examples:</div>
                            <ul className="list-disc list-inside mt-1">
                              {cluster.examples.map((example: string, exIndex: number) => (
                                <li key={exIndex} className="truncate">{example}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Anomalies */}
                {aiAnalysisData.anomalies && aiAnalysisData.anomalies.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Detected Anomalies:</p>
                    <div className="space-y-2">
                      {aiAnalysisData.anomalies.map((anomaly: any, index: number) => (
                        <div key={index} className="bg-secondary p-3 rounded-md border-l-4 border-terminal-error">
                          <div className="font-semibold">
                            {anomaly.type === 'statistical_outlier' ? 'Statistical Outlier' : anomaly.type}
                          </div>
                          <div className="text-sm">{anomaly.description}</div>
                          {anomaly.log && (
                            <div className="text-xs text-muted-foreground mt-1 truncate">
                              {anomaly.log.Message}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Top patterns */}
                {aiAnalysisData.top_patterns && aiAnalysisData.top_patterns.length > 0 && (
                  <div className="space-y-2">
                    <p className="font-semibold">Common Terms:</p>
                    <div className="flex flex-wrap gap-2">
                      {aiAnalysisData.top_patterns.slice(0, 10).map(([term, count]: [string, number], index: number) => (
                        <div key={index} className="bg-secondary px-2 py-1 rounded text-xs">
                          {term} ({count})
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                <p className="text-terminal-info font-semibold mt-2">
                  AI analysis complete. Using unsupervised learning (K-means clustering, PCA & statistical anomaly detection) for pattern recognition.
                  {aiAnalysisData.anomalies?.length ? ` ${aiAnalysisData.anomalies.length} anomalies detected.` : ' No significant anomalies detected.'}
                </p>
              </div>
            ),
            type: 'jsx'
          };
        } catch (error) {
          return { 
            content: `Error performing AI log analysis: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'ping':
        if (!args.length) {
          return { content: 'Usage: ping <hostname>', type: 'error' };
        }
        
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Execute the real ping command
          const pingCommand = `ping ${args[0]} ${process.platform === 'win32' ? '-n 4' : '-c 4'}`;
          const output = await executeShellCommand(pingCommand);
          return { content: output, type: 'standard' };
        } catch (error) {
          return { 
            content: `Error executing ping command: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'ifconfig':
      case 'ipconfig':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Execute the appropriate command based on the OS
          const command = process.platform === 'win32' ? 'ipconfig' : 'ifconfig';
          const output = await executeShellCommand(command);
          return { content: output, type: 'standard' };
        } catch (error) {
          return { 
            content: `Error executing network command: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'ps':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Execute the ps command
          const command = process.platform === 'win32' ? 'tasklist' : 'ps aux | head -20';
          const output = await executeShellCommand(command);
          return { content: output, type: 'standard' };
        } catch (error) {
          return { 
            content: `Error executing ps command: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'ls':
      case 'dir':
        try {
          if (!isElectron()) {
            return { 
              content: 'This feature requires Electron with full system access',
              type: 'error' 
            };
          }
          
          // Execute the appropriate command based on the OS
          const path = args.length > 0 ? args[0] : '.';
          const command = process.platform === 'win32' ? `dir ${path}` : `ls -la ${path}`;
          const output = await executeShellCommand(command);
          return { content: output, type: 'standard' };
        } catch (error) {
          return { 
            content: `Error executing directory listing command: ${(error as Error).message}`,
            type: 'error' 
          };
        }
      
      case 'clear':
        return { content: '', type: 'standard' };
      
      case 'exit':
        return { content: 'Goodbye!', type: 'info' };
      
      default:
        if (command.trim() !== '') {
          try {
            if (!isElectron()) {
              return { 
                content: 'This feature requires Electron with full system access',
                type: 'error' 
              };
            }
            
            // Try to execute the command directly
            const output = await executeShellCommand(command);
            return { content: output, type: 'standard' };
          } catch (error) {
            return { 
              content: `Command not found: ${mainCommand}. Type 'help' to see available commands.`, 
              type: 'error' 
            };
          }
        }
        return { content: '', type: 'standard' };
    }
  } catch (error) {
    return { 
      content: `Error executing command: ${(error as Error).message}`, 
      type: 'error' 
    };
  }
}
