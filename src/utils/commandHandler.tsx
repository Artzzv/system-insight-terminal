
import React from 'react';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';

interface CommandResult {
  content: React.ReactNode;
  type: 'standard' | 'success' | 'error' | 'warning' | 'info' | 'jsx';
}

// Simulated network check results
const networkDevices = [
  { name: 'eth0', status: 'connected', ip: '192.168.1.100', mac: '00:1A:2B:3C:4D:5E' },
  { name: 'wlan0', status: 'connected', ip: '192.168.1.101', mac: '00:1A:2B:3C:4D:5F' },
  { name: 'lo', status: 'connected', ip: '127.0.0.1', mac: '00:00:00:00:00:00' },
];

// Simulated system health
const systemHealth = {
  cpu: { usage: 45, temp: 65, cores: 8 },
  memory: { total: 16384, used: 8192, free: 8192 },
  disk: { total: 512, used: 256, free: 256 },
  uptime: '5 days, 7 hours, 23 minutes',
  processes: 143,
};

// Simulated security policies
const securityPolicies = [
  { id: 'POL001', name: 'Password Policy', status: 'Enforced', lastUpdated: '2023-12-15' },
  { id: 'POL002', name: 'Firewall Rules', status: 'Enforced', lastUpdated: '2024-01-20' },
  { id: 'POL003', name: 'Access Control', status: 'Partially Enforced', lastUpdated: '2024-03-10' },
  { id: 'POL004', name: 'Data Encryption', status: 'Enforced', lastUpdated: '2024-02-28' },
  { id: 'POL005', name: 'Audit Logging', status: 'Enforced', lastUpdated: '2024-04-01' },
];

// Simulated log entries
const logEntries = [
  { timestamp: '2024-04-08 10:15:23', level: 'INFO', service: 'Authentication', message: 'User login successful: admin' },
  { timestamp: '2024-04-08 10:16:45', level: 'WARNING', service: 'Firewall', message: 'Blocked connection attempt from 203.0.113.42:4455' },
  { timestamp: '2024-04-08 10:18:12', level: 'ERROR', service: 'Database', message: 'Connection timeout after 30s' },
  { timestamp: '2024-04-08 10:20:30', level: 'INFO', service: 'FileSystem', message: 'Backup completed successfully' },
  { timestamp: '2024-04-08 10:22:15', level: 'WARNING', service: 'Authentication', message: 'Failed login attempt for user: guest' },
];

// Help information
const helpInfo = `
Available commands:

Basic Commands:
  help                Display this help information
  clear               Clear the terminal screen
  exit                Exit the terminal session

System Commands:
  system-health       Display system health metrics
  ps                  List running processes
  top                 Display system resource usage (interactive)
  df                  Show disk space usage
  free                Display memory usage

Network Commands:
  network-check       Check network interfaces and connectivity
  ping <host>         Ping a host
  ifconfig            Display network interfaces
  netstat             Display network connections
  traceroute <host>   Trace the route to a host

Security Commands:
  audit               Run a security audit
  show-policies       Display security policies
  analyze-logs        Analyze system logs
  scan-ports          Scan for open ports
  check-updates       Check for security updates

File Operations:
  ls [dir]            List directory contents
  cd <dir>            Change directory
  pwd                 Print working directory
  cat <file>          Display file content
  find <pattern>      Search for files

Type any command to execute it.
`;

export async function executeCommand(command: string): Promise<CommandResult> {
  // Simulate command execution delay
  await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 200));
  
  const parts = command.trim().split(' ');
  const mainCommand = parts[0].toLowerCase();
  const args = parts.slice(1);
  
  switch (mainCommand) {
    case 'help':
      return { content: helpInfo, type: 'info' };
    
    case 'network-check':
      return { 
        content: (
          <div className="space-y-2">
            <p>Performing network check...</p>
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
                  {networkDevices.map((device, index) => (
                    <tr key={index}>
                      <td className="pr-4">{device.name}</td>
                      <td className={`pr-4 ${device.status === 'connected' ? 'text-terminal-success' : 'text-terminal-error'}`}>
                        {device.status}
                      </td>
                      <td className="pr-4">{device.ip}</td>
                      <td>{device.mac}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              
              <p className="font-semibold mt-4">Connectivity Tests:</p>
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span>Default Gateway (192.168.1.1):</span>
                  <span className="text-terminal-success">Connected (2ms)</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>DNS Server (8.8.8.8):</span>
                  <span className="text-terminal-success">Connected (45ms)</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>Internet (google.com):</span>
                  <span className="text-terminal-success">Connected (78ms)</span>
                </div>
              </div>
              
              <p className="text-terminal-success font-semibold mt-2">
                Network check completed successfully. All systems operational.
              </p>
            </div>
          </div>
        ),
        type: 'jsx'
      };
    
    case 'system-health':
      return {
        content: (
          <div className="space-y-4">
            <p>System Health Report:</p>
            
            <div className="space-y-2">
              <p className="font-semibold">CPU:</p>
              <div className="flex items-center space-x-2">
                <div className="flex-1">
                  <Progress value={systemHealth.cpu.usage} className="h-2" />
                </div>
                <span>{systemHealth.cpu.usage}%</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>Temperature: <span className={systemHealth.cpu.temp > 80 ? 'text-terminal-error' : 'text-terminal-success'}>
                  {systemHealth.cpu.temp}°C
                </span></div>
                <div>Cores: {systemHealth.cpu.cores}</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <p className="font-semibold">Memory:</p>
              <div className="flex items-center space-x-2">
                <div className="flex-1">
                  <Progress value={(systemHealth.memory.used / systemHealth.memory.total) * 100} className="h-2" />
                </div>
                <span>{Math.round((systemHealth.memory.used / systemHealth.memory.total) * 100)}%</span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-sm">
                <div>Total: {systemHealth.memory.total} MB</div>
                <div>Used: {systemHealth.memory.used} MB</div>
                <div>Free: {systemHealth.memory.free} MB</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <p className="font-semibold">Disk Space:</p>
              <div className="flex items-center space-x-2">
                <div className="flex-1">
                  <Progress value={(systemHealth.disk.used / systemHealth.disk.total) * 100} className="h-2" />
                </div>
                <span>{Math.round((systemHealth.disk.used / systemHealth.disk.total) * 100)}%</span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-sm">
                <div>Total: {systemHealth.disk.total} GB</div>
                <div>Used: {systemHealth.disk.used} GB</div>
                <div>Free: {systemHealth.disk.free} GB</div>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4 text-sm mt-2">
              <div>
                <span className="font-semibold">System Uptime:</span> {systemHealth.uptime}
              </div>
              <div>
                <span className="font-semibold">Processes:</span> {systemHealth.processes}
              </div>
            </div>
            
            <p className="text-terminal-success font-semibold mt-2">
              System health check completed. Overall status: Good
            </p>
          </div>
        ),
        type: 'jsx'
      };
    
    case 'audit':
      return {
        content: (
          <div className="space-y-4">
            <p>Running security audit...</p>
            
            <div className="space-y-2">
              <div className="flex justify-between">
                <span>Checking user permissions...</span>
                <span className="text-terminal-success">Passed</span>
              </div>
              <div className="flex justify-between">
                <span>Verifying file permissions...</span>
                <span className="text-terminal-warning">Warnings found</span>
              </div>
              <div className="flex justify-between">
                <span>Scanning for vulnerable software...</span>
                <span className="text-terminal-error">Issues found</span>
              </div>
              <div className="flex justify-between">
                <span>Checking firewall configuration...</span>
                <span className="text-terminal-success">Passed</span>
              </div>
              <div className="flex justify-between">
                <span>Auditing password policies...</span>
                <span className="text-terminal-success">Passed</span>
              </div>
            </div>
            
            <Separator />
            
            <div>
              <p className="font-semibold">Issues found:</p>
              <ul className="list-disc list-inside space-y-1 mt-1">
                <li className="text-terminal-warning">
                  /etc/shadow has incorrect permissions (644, should be 600)
                </li>
                <li className="text-terminal-error">
                  OpenSSL version 1.1.1 is vulnerable (CVE-2023-0286)
                </li>
                <li className="text-terminal-error">
                  Apache httpd 2.4.49 is vulnerable (CVE-2021-41773)
                </li>
              </ul>
            </div>
            
            <div>
              <p className="font-semibold">Recommendations:</p>
              <ul className="list-disc list-inside space-y-1 mt-1">
                <li>Update OpenSSL to version 1.1.1t or later</li>
                <li>Update Apache httpd to version 2.4.53 or later</li>
                <li>Fix file permissions: chmod 600 /etc/shadow</li>
              </ul>
            </div>
            
            <p className="text-terminal-warning font-semibold mt-2">
              Audit completed with 1 warning and 2 critical issues.
            </p>
          </div>
        ),
        type: 'jsx'
      };
    
    case 'show-policies':
      return {
        content: (
          <div className="space-y-4">
            <p>Security Policies:</p>
            
            <div className="space-y-2">
              <table className="min-w-full">
                <thead>
                  <tr>
                    <th className="text-left pr-4">ID</th>
                    <th className="text-left pr-4">Policy</th>
                    <th className="text-left pr-4">Status</th>
                    <th className="text-left">Last Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {securityPolicies.map((policy, index) => (
                    <tr key={index}>
                      <td className="pr-4">{policy.id}</td>
                      <td className="pr-4">{policy.name}</td>
                      <td className={`pr-4 ${
                        policy.status === 'Enforced' 
                          ? 'text-terminal-success' 
                          : policy.status === 'Partially Enforced' 
                            ? 'text-terminal-warning' 
                            : 'text-terminal-error'
                      }`}>
                        {policy.status}
                      </td>
                      <td>{policy.lastUpdated}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <p className="mt-2">
              To view details of a specific policy, use: <span className="text-terminal-command">show-policies --detail POL001</span>
            </p>
          </div>
        ),
        type: 'jsx'
      };
    
    case 'analyze-logs':
      return {
        content: (
          <div className="space-y-4">
            <p>Log Analysis:</p>
            
            <div className="space-y-2">
              <table className="min-w-full">
                <thead>
                  <tr>
                    <th className="text-left pr-4">Timestamp</th>
                    <th className="text-left pr-4">Level</th>
                    <th className="text-left pr-4">Service</th>
                    <th className="text-left">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {logEntries.map((log, index) => (
                    <tr key={index}>
                      <td className="pr-4 text-xs">{log.timestamp}</td>
                      <td className={`pr-4 ${
                        log.level === 'ERROR' 
                          ? 'text-terminal-error' 
                          : log.level === 'WARNING' 
                            ? 'text-terminal-warning' 
                            : 'text-terminal-info'
                      }`}>
                        {log.level}
                      </td>
                      <td className="pr-4">{log.service}</td>
                      <td>{log.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <div className="space-y-2">
              <p className="font-semibold">Summary:</p>
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-secondary p-2 rounded flex flex-col items-center">
                  <span className="text-terminal-info font-bold text-lg">2</span>
                  <span className="text-xs">INFO</span>
                </div>
                <div className="bg-secondary p-2 rounded flex flex-col items-center">
                  <span className="text-terminal-warning font-bold text-lg">2</span>
                  <span className="text-xs">WARNING</span>
                </div>
                <div className="bg-secondary p-2 rounded flex flex-col items-center">
                  <span className="text-terminal-error font-bold text-lg">1</span>
                  <span className="text-xs">ERROR</span>
                </div>
              </div>
            </div>
            
            <p className="mt-2">
              For more detailed analysis, use: <span className="text-terminal-command">analyze-logs --service Authentication</span>
            </p>
          </div>
        ),
        type: 'jsx'
      };
    
    case 'ping':
      if (!args.length) {
        return { content: 'Usage: ping <hostname>', type: 'error' };
      }
      return { 
        content: `Pinging ${args[0]} [${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}] with 32 bytes of data:
Reply from ${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}: bytes=32 time=${Math.floor(Math.random() * 20) + 5}ms TTL=64
Reply from ${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}: bytes=32 time=${Math.floor(Math.random() * 20) + 5}ms TTL=64
Reply from ${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}: bytes=32 time=${Math.floor(Math.random() * 20) + 5}ms TTL=64
Reply from ${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}: bytes=32 time=${Math.floor(Math.random() * 20) + 5}ms TTL=64

Ping statistics for ${args[0]}:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = ${Math.floor(Math.random() * 10) + 5}ms, Maximum = ${Math.floor(Math.random() * 30) + 15}ms, Average = ${Math.floor(Math.random() * 20) + 10}ms`,
        type: 'standard'
      };
    
    case 'ls':
      return { 
        content: `drwxr-xr-x  5 user  staff   160 Apr  8 10:45 .
drwxr-xr-x  3 user  staff    96 Apr  8 10:30 ..
-rw-r--r--  1 user  staff  2489 Apr  8 10:35 audit_config.json
drwxr-xr-x  8 user  staff   256 Apr  8 10:40 logs
-rwxr-xr-x  1 user  staff  8544 Apr  8 10:32 network_scanner.py
drwxr-xr-x 12 user  staff   384 Apr  8 10:37 reports
drwxr-xr-x  4 user  staff   128 Apr  8 10:42 scripts
-rw-r--r--  1 user  staff  4562 Apr  8 10:33 security_policy.xml
-rwxr-xr-x  1 user  staff 12680 Apr  8 10:31 system_monitor.py`, 
        type: 'standard'
      };
    
    case 'ifconfig':
      return { 
        content: `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1a:2b3c:4d5e  prefixlen 64  scopeid 0x20<link>
        ether 00:1A:2B:3C:4D:5E  txqueuelen 1000  (Ethernet)
        RX packets 846587  bytes 1234586754 (1.1 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 563821  bytes 68573418 (65.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.101  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1a:2b3c:4d5f  prefixlen 64  scopeid 0x20<link>
        ether 00:1A:2B:3C:4D:5F  txqueuelen 1000  (Ethernet)
        RX packets 124568  bytes 178965423 (170.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 87654  bytes 12345678 (11.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 78654  bytes 8765432 (8.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 78654  bytes 8765432 (8.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0`, 
        type: 'standard'
      };
    
    case 'ps':
      return { 
        content: `  PID TTY          TIME CMD
  1234 pts/0    00:00:01 bash
  2345 pts/0    00:00:00 ps
  3456 pts/1    00:05:23 system_monitor.py
  4567 pts/1    00:01:45 network_scanner.py
  5678 pts/1    00:00:12 audit.py
  6789 ?        01:23:45 systemd
  7890 ?        00:34:56 NetworkManager
  8901 ?        00:12:34 sshd
  9012 ?        00:23:45 cron
  1122 ?        00:56:43 apache2
  2233 ?        00:32:12 mysql`, 
        type: 'standard'
      };
    
    case 'clear':
      return { content: '', type: 'standard' };
    
    case 'exit':
      return { content: 'Goodbye!', type: 'info' };
    
    default:
      if (command.trim() !== '') {
        return { 
          content: `Command not found: ${mainCommand}. Type 'help' to see available commands.`, 
          type: 'error' 
        };
      }
      return { content: '', type: 'standard' };
  }
}
