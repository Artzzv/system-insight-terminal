
const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld(
  'api', {
    send: (channel, data) => {
      // whitelist channels
      let validChannels = ['get-system-info', 'get-cpu-info', 'get-memory-info', 'execute-command'];
      if (validChannels.includes(channel)) {
        ipcRenderer.send(channel, data);
      }
    },
    receive: (channel, func) => {
      let validChannels = ['system-info', 'cpu-info', 'memory-info', 'command-result'];
      if (validChannels.includes(channel)) {
        // Deliberately strip event as it includes `sender` 
        ipcRenderer.on(channel, (event, ...args) => func(...args));
      }
    },
    // Directly expose Node.js modules for use in the renderer process
    // This is to allow direct access from systemInfo.ts
    node: {
      os: () => {
        return window.require('os');
      },
      childProcess: () => {
        return window.require('child_process');
      },
      fs: () => {
        return window.require('fs');
      }
    }
  }
);
