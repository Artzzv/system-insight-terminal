
@echo off
start "Vite Dev Server" /min npm run dev
timeout /t 3
node electron-start.js
