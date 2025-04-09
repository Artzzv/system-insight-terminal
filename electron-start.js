
const { spawn } = require('child_process');
const electron = require('electron');
const path = require('path');

// Set environment to development
process.env.NODE_ENV = 'development';
process.env.ELECTRON_START_URL = 'http://localhost:5173';

// Start the Electron app
const child = spawn(electron, [path.join(__dirname, 'src/electron/main.js')], {
  stdio: 'inherit'
});

child.on('close', (code) => {
  console.log(`Electron process exited with code ${code}`);
  process.exit(code);
});
