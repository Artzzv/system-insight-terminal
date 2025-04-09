
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const url = require('url');
const { exec, execSync } = require('child_process');
const os = require('os');
const si = require('systeminformation');
const fs = require('fs');
const { promisify } = require('util');
const execPromise = promisify(exec);

// AI model for log analysis
const { LogAnalyzer } = require('./logAnalyzer');

let mainWindow;
let logAnalyzer;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false, // Disable sandbox to allow executing commands
      preload: path.join(__dirname, 'preload.js')
    }
  });

  const startUrl = process.env.ELECTRON_START_URL || url.format({
    pathname: path.join(__dirname, '../../dist/index.html'),
    protocol: 'file:',
    slashes: true
  });

  mainWindow.loadURL(startUrl);

  // Open DevTools in development
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

app.on('ready', () => {
  createWindow();
  
  // Initialize the log analyzer with unsupervised learning
  logAnalyzer = new LogAnalyzer();
  logAnalyzer.initialize();
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', function () {
  if (mainWindow === null) {
    createWindow();
  }
});

// Handle IPC messages from renderer
ipcMain.on('execute-command', async (event, command) => {
  try {
    const { stdout, stderr } = await execPromise(command);
    event.reply('command-result', {
      success: true,
      stdout
    });
  } catch (error) {
    event.reply('command-result', {
      success: false,
      error: error.message,
      stderr: error.stderr
    });
  }
});

// Handle system info requests
ipcMain.on('get-system-info', async (event) => {
  try {
    const systemInfo = {
      hostname: os.hostname(),
      platform: os.platform() + ' ' + os.release(),
      arch: os.arch(),
      cpus: os.cpus(),
      totalmem: os.totalmem(),
      freemem: os.freemem(),
      uptime: os.uptime(),
      boot_time: new Date(Date.now() - (os.uptime() * 1000)).toISOString()
    };
    
    event.reply('system-info', systemInfo);
  } catch (error) {
    console.error('Error getting system info:', error);
    event.reply('system-info', { error: error.message });
  }
});

// Handle CPU info requests
ipcMain.on('get-cpu-info', async (event) => {
  try {
    const cpuData = await si.cpu();
    const currentLoad = await si.currentLoad();
    
    const cpuInfo = {
      physical_cores: cpuData.physicalCores,
      total_cores: cpuData.cores,
      cpu_usage_per_core: currentLoad.cpus.map(core => core.load),
      total_cpu_usage: currentLoad.currentLoad,
      cpu_frequency: {
        current: cpuData.speed,
        min: cpuData.speedMin || cpuData.speed * 0.6,
        max: cpuData.speedMax || cpuData.speed * 1.2
      },
      model: cpuData.manufacturer + ' ' + cpuData.brand
    };
    
    event.reply('cpu-info', cpuInfo);
  } catch (error) {
    console.error('Error getting CPU info:', error);
    event.reply('cpu-info', { error: error.message });
  }
});

// Handle memory info requests
ipcMain.on('get-memory-info', async (event) => {
  try {
    const memData = await si.mem();
    const swapData = await si.memLayout();
    
    const memInfo = {
      virtual_memory: {
        total: memData.total,
        available: memData.available,
        used: memData.used,
        percentage: Math.round((memData.used / memData.total) * 100)
      },
      swap: {
        total: memData.swaptotal,
        used: memData.swapused,
        free: memData.swaptotal - memData.swapused,
        percentage: Math.round((memData.swapused / (memData.swaptotal || 1)) * 100)
      }
    };
    
    event.reply('memory-info', memInfo);
  } catch (error) {
    console.error('Error getting memory info:', error);
    event.reply('memory-info', { error: error.message });
  }
});

// Handle disk info requests
ipcMain.on('get-disk-info', async (event) => {
  try {
    const fsData = await si.fsSize();
    
    const diskInfo = {
      partitions: fsData.map(partition => ({
        device: partition.fs,
        mountpoint: partition.mount,
        fstype: partition.type,
        total_size: partition.size,
        used: partition.used,
        free: partition.size - partition.used,
        percentage: Math.round((partition.used / partition.size) * 100)
      }))
    };
    
    event.reply('disk-info', diskInfo);
  } catch (error) {
    console.error('Error getting disk info:', error);
    event.reply('disk-info', { error: error.message });
  }
});

// Handle network info requests
ipcMain.on('get-network-info', async (event) => {
  try {
    const interfaces = await si.networkInterfaces();
    const stats = await si.networkStats();
    const connections = await si.networkConnections();
    
    const networkInfo = {
      interfaces: interfaces.reduce((acc, iface) => {
        acc[iface.iface] = {
          ip: iface.ip4,
          mac: iface.mac,
          netmask: iface.ip4subnet
        };
        return acc;
      }, {}),
      io_counters: stats.reduce((acc, stat) => {
        acc.bytes_sent = (acc.bytes_sent || 0) + stat.tx_bytes;
        acc.bytes_received = (acc.bytes_received || 0) + stat.rx_bytes;
        acc.packets_sent = (acc.packets_sent || 0) + stat.tx_packets;
        acc.packets_received = (acc.packets_received || 0) + stat.rx_packets;
        return acc;
      }, {
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0
      }),
      connections: connections.slice(0, 100).map(conn => ({
        type: conn.protocol,
        local_address: `${conn.localAddress}:${conn.localPort}`,
        remote_address: `${conn.peerAddress}:${conn.peerPort}`,
        status: conn.state
      }))
    };
    
    event.reply('network-info', networkInfo);
  } catch (error) {
    console.error('Error getting network info:', error);
    event.reply('network-info', { error: error.message });
  }
});

// Handle Windows Event Log requests
ipcMain.on('get-event-logs', async (event, options) => {
  try {
    const { logName, count, filter } = options || { logName: 'System', count: 50 };
    
    // Query Windows Event Logs using PowerShell
    let command = `powershell -Command "Get-WinEvent -LogName ${logName} -MaxEvents ${count}`;
    
    if (filter) {
      command += ` -FilterXPath '*[System[(${filter})]]'`;
    }
    
    command += ` | Select-Object TimeCreated,Id,LevelDisplayName,Message,ProviderName | ConvertTo-Json"`;
    
    const { stdout } = await execPromise(command);
    const logs = JSON.parse(stdout);
    
    event.reply('event-logs-result', {
      success: true,
      logs
    });
  } catch (error) {
    console.error('Error getting Windows event logs:', error);
    event.reply('event-logs-result', {
      success: false,
      error: error.message
    });
  }
});

// Handle Windows Defender status request
ipcMain.on('get-defender-status', async (event) => {
  try {
    const { stdout } = await execPromise('powershell -Command "Get-MpComputerStatus | ConvertTo-Json"');
    const defenderStatus = JSON.parse(stdout);
    
    event.reply('defender-status-result', {
      success: true,
      status: defenderStatus
    });
  } catch (error) {
    console.error('Error getting Windows Defender status:', error);
    event.reply('defender-status-result', {
      success: false,
      error: error.message
    });
  }
});

// Handle Firewall rules request
ipcMain.on('get-firewall-rules', async (event) => {
  try {
    const { stdout } = await execPromise('powershell -Command "Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Select-Object Name,DisplayName,Direction,Action,Profile | ConvertTo-Json -Depth 2"');
    const firewallRules = JSON.parse(stdout);
    
    event.reply('firewall-rules-result', {
      success: true,
      rules: firewallRules
    });
  } catch (error) {
    console.error('Error getting firewall rules:', error);
    event.reply('firewall-rules-result', {
      success: false,
      error: error.message
    });
  }
});

// Handle AI log analysis request
ipcMain.on('analyze-logs-ai', async (event, options) => {
  try {
    const { logName, count } = options || { logName: 'System', count: 1000 };
    
    // Get logs for analysis
    const { stdout } = await execPromise(`powershell -Command "Get-WinEvent -LogName ${logName} -MaxEvents ${count} | Select-Object TimeCreated,Id,LevelDisplayName,Message,ProviderName | ConvertTo-Json"`);
    const logs = JSON.parse(stdout);
    
    // Use the AI model to analyze logs
    const analysisResult = await logAnalyzer.analyzeLogs(logs);
    
    event.reply('ai-analysis-result', {
      success: true,
      result: analysisResult
    });
  } catch (error) {
    console.error('Error performing AI log analysis:', error);
    event.reply('ai-analysis-result', {
      success: false,
      error: error.message
    });
  }
});

// Handle security audit request
ipcMain.on('run-security-audit', async (event) => {
  try {
    // Use PowerShell to get security-related information
    const [defenderOutput, firewallOutput, securityUpdatesOutput] = await Promise.all([
      execPromise('powershell -Command "Get-MpComputerStatus | ConvertTo-Json"'),
      execPromise('powershell -Command "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"'),
      execPromise('powershell -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | ConvertTo-Json"')
    ]);
    
    const defender = JSON.parse(defenderOutput.stdout);
    const firewall = JSON.parse(firewallOutput.stdout);
    const updates = JSON.parse(securityUpdatesOutput.stdout);
    
    // Generate security audit report
    const issues = [];
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    
    // Check Windows Defender status
    if (!defender.RealTimeProtectionEnabled) {
      issues.push({
        severity: 'high',
        issue: 'Real-time protection is disabled',
        recommendation: 'Enable real-time protection in Windows Defender'
      });
      highCount++;
    }
    
    if (!defender.AntivirusEnabled) {
      issues.push({
        severity: 'high',
        issue: 'Antivirus is disabled',
        recommendation: 'Enable Windows Defender antivirus'
      });
      highCount++;
    }
    
    // Check firewall status
    const disabledProfiles = firewall.filter(profile => !profile.Enabled);
    if (disabledProfiles.length > 0) {
      issues.push({
        severity: 'high',
        issue: `Firewall is disabled for profiles: ${disabledProfiles.map(p => p.Name).join(', ')}`,
        recommendation: 'Enable firewall for all network profiles'
      });
      highCount++;
    }
    
    // Check updates
    const lastUpdate = updates.length > 0 ? new Date(updates[0].InstalledOn) : null;
    const daysSinceLastUpdate = lastUpdate ? Math.floor((new Date() - lastUpdate) / (1000 * 60 * 60 * 24)) : null;
    
    if (daysSinceLastUpdate && daysSinceLastUpdate > 30) {
      issues.push({
        severity: 'medium',
        issue: `No security updates installed in the last ${daysSinceLastUpdate} days`,
        recommendation: 'Install the latest Windows security updates'
      });
      mediumCount++;
    }
    
    // Additional checks can be added here
    
    const auditResult = {
      hostname: os.hostname(),
      issues_by_severity: { high: highCount, medium: mediumCount, low: lowCount },
      issues: issues,
      defender_status: {
        realtime_protection: defender.RealTimeProtectionEnabled,
        antivirus_enabled: defender.AntivirusEnabled,
        definitions_updated: defender.AntivirusSignatureLastUpdated
      },
      firewall_status: firewall,
      last_updates: updates
    };
    
    event.reply('security-audit-result', {
      success: true,
      audit: auditResult
    });
  } catch (error) {
    console.error('Error running security audit:', error);
    event.reply('security-audit-result', {
      success: false,
      error: error.message
    });
  }
});
