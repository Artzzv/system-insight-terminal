
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const url = require('url');
const { exec } = require('child_process');
const os = require('os');

let mainWindow;

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

app.on('ready', createWindow);

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
ipcMain.on('execute-command', (event, command) => {
  exec(command, (error, stdout, stderr) => {
    if (error) {
      event.reply('command-result', {
        success: false,
        error: error.message,
        stderr
      });
    } else {
      event.reply('command-result', {
        success: true,
        stdout
      });
    }
  });
});

// Handle system info requests
ipcMain.on('get-system-info', (event) => {
  const systemInfo = {
    hostname: os.hostname(),
    platform: os.platform() + ' ' + os.release(),
    arch: os.arch(),
    cpus: os.cpus(),
    totalmem: os.totalmem(),
    freemem: os.freemem(),
    uptime: os.uptime()
  };
  
  event.reply('system-info', systemInfo);
});

// Handle CPU info requests
ipcMain.on('get-cpu-info', (event) => {
  const cpus = os.cpus();
  event.reply('cpu-info', cpus);
});

// Handle memory info requests
ipcMain.on('get-memory-info', (event) => {
  const memInfo = {
    total: os.totalmem(),
    free: os.freemem()
  };
  event.reply('memory-info', memInfo);
});
