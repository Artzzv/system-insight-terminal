
import React, { useState, useRef, useEffect } from 'react';
import { v4 as uuidv4 } from 'uuid';
import TerminalHeader from './TerminalHeader';
import TerminalOutput, { TerminalOutputLine, OutputType } from './TerminalOutput';
import TerminalInput from './TerminalInput';
import { executeCommand } from '@/utils/commandHandler';
import { Separator } from '@/components/ui/separator';

interface TerminalProps {
  title?: string;
  initialOutput?: TerminalOutputLine[];
  initialPrompt?: string;
}

const Terminal: React.FC<TerminalProps> = ({
  title = 'System Insight Terminal',
  initialOutput = [],
  initialPrompt = 'system@audit:~$ ',
}) => {
  const [outputLines, setOutputLines] = useState<TerminalOutputLine[]>(initialOutput);
  const [input, setInput] = useState('');
  const [prompt, setPrompt] = useState(initialPrompt);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isServerConnected, setIsServerConnected] = useState(false);
  const [isServerChecking, setIsServerChecking] = useState(true);

  const terminalRef = useRef<HTMLDivElement>(null);

  // Common commands for autocompletion
  const commonCommands = [
    'help', 'clear', 'network-check', 'system-health', 'audit', 
    'show-policies', 'analyze-logs', 'ai-analyze-logs', 'exit', 'ls', 'cd', 'pwd',
    'ifconfig', 'ipconfig', 'ping', 'traceroute', 'netstat', 'arp',
    'ps', 'top', 'htop', 'df', 'du', 'free',
    'cat', 'grep', 'find', 'chmod', 'chown', 'history'
  ];

  // Check if backend server is running
  useEffect(() => {
    const checkServerConnection = async () => {
      try {
        const response = await fetch('http://localhost:5000/health');
        setIsServerConnected(response.ok);
      } catch (error) {
        setIsServerConnected(false);
      } finally {
        setIsServerChecking(false);
      }
    };

    checkServerConnection();
  }, []);

  // Auto-scroll to bottom when output changes
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [outputLines]);

  const addOutputLine = (content: React.ReactNode, type: OutputType = 'standard') => {
    setOutputLines((prev) => [
      ...prev,
      { id: uuidv4(), type, content, timestamp: new Date() },
    ]);
  };

  const handleSubmit = async (command: string) => {
    if (!command.trim()) return;

    // Add the command to history
    setHistory((prev) => [...prev, command]);
    setHistoryIndex(-1);

    // Display the command
    addOutputLine(`${prompt}${command}`, 'command');

    setIsProcessing(true);

    try {
      // If server is not connected, show a warning message for commands that need the backend
      if (!isServerConnected && !['help', 'clear', 'exit'].includes(command.trim().toLowerCase())) {
        addOutputLine(
          <div className="space-y-2">
            <p className="text-terminal-warning">Backend server not connected!</p>
            <p>The backend server appears to be offline. Some commands will not function properly.</p>
            <p>Please make sure the Flask backend server is running:</p>
            <ol className="list-decimal list-inside space-y-1 ml-4">
              <li>Navigate to the backend directory</li>
              <li>Install dependencies: <code>pip install flask flask_cors psutil netifaces cryptography</code></li>
              <li>Run the server: <code>python app.py</code></li>
            </ol>
            <p>Only basic commands like 'help', 'clear', and 'exit' will work without the backend.</p>
          </div>,
          'warning'
        );
        
        if (command.trim() !== 'help' && command.trim() !== 'clear' && command.trim() !== 'exit') {
          setIsProcessing(false);
          setInput('');
          return;
        }
      }
      
      // Process the command
      const result = await executeCommand(command);
      
      // Display the result based on its type
      if (result.type === 'error') {
        addOutputLine(result.content, 'error');
      } else if (result.type === 'success') {
        addOutputLine(result.content, 'success');
      } else if (result.type === 'warning') {
        addOutputLine(result.content, 'warning');
      } else if (result.type === 'info') {
        addOutputLine(result.content, 'info');
      } else if (result.type === 'jsx') {
        addOutputLine(result.content);
      } else {
        addOutputLine(result.content);
      }

      // Handle special commands
      if (command.trim() === 'clear') {
        setOutputLines([]);
      } else if (command.trim() === 'exit') {
        addOutputLine('Exiting terminal session...', 'info');
        // Additional exit logic can be added here
      }
    } catch (error) {
      addOutputLine(`Error: ${(error as Error).message}`, 'error');
    } finally {
      setIsProcessing(false);
      setInput('');
    }
  };

  const handleHistoryNavigation = (direction: 'up' | 'down') => {
    if (history.length === 0) return;

    if (direction === 'up') {
      const newIndex = historyIndex < 0 ? history.length - 1 : historyIndex - 1;
      if (newIndex >= 0) {
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      }
    } else {
      const newIndex = historyIndex + 1;
      if (newIndex < history.length) {
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      } else {
        setHistoryIndex(-1);
        setInput('');
      }
    }
  };

  // Start with welcome message
  useEffect(() => {
    if (outputLines.length === 0) {
      addOutputLine(`Welcome to System Insight Terminal v1.1.0`, 'info');
      addOutputLine(`Type 'help' to see available commands`, 'info');
      
      if (isServerChecking) {
        addOutputLine('Checking connection to backend server...', 'standard');
      } else if (!isServerConnected) {
        addOutputLine(
          <div className="space-y-2">
            <p className="text-terminal-warning">Backend server not connected!</p>
            <p>To enable full functionality, please start the backend server:</p>
            <ol className="list-decimal list-inside space-y-1 ml-4">
              <li>Navigate to the backend directory</li>
              <li>Install dependencies: <code>pip install flask flask_cors psutil netifaces cryptography</code></li>
              <li>Run the server: <code>python app.py</code></li>
            </ol>
            <p>Only basic commands like 'help', 'clear', and 'exit' will work without the backend.</p>
          </div>,
          'warning'
        );
      } else {
        addOutputLine('Connected to backend server successfully!', 'success');
        addOutputLine(`Real-time system monitoring is now available.`, 'success');
      }
      
      addOutputLine('', 'standard');
    }
  }, [outputLines.length, isServerConnected, isServerChecking]);

  return (
    <div className="flex flex-col h-full border border-border rounded-md overflow-hidden bg-terminal-dark shadow-lg">
      <TerminalHeader title={title} />
      
      <div ref={terminalRef} className="terminal-window flex-1 overflow-auto">
        <TerminalOutput lines={outputLines} showTimestamps={true} />
        
        <div className="mt-2">
          <TerminalInput
            prompt={prompt}
            value={input}
            onChange={setInput}
            onSubmit={handleSubmit}
            history={history}
            historyIndex={historyIndex}
            onHistoryNavigation={handleHistoryNavigation}
            suggestions={commonCommands}
            disabled={isProcessing}
          />
        </div>
      </div>
      
      {!isServerConnected && !isServerChecking && (
        <div className="p-2 bg-terminal-error/20 border-t border-terminal-error">
          <div className="text-xs text-terminal-error flex items-center justify-between">
            <span>Backend server not connected. Limited functionality available.</span>
            <button 
              className="px-2 py-1 bg-terminal-dark text-xs rounded border border-terminal-error hover:bg-terminal-error/20"
              onClick={() => window.location.reload()}
            >
              Retry Connection
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Terminal;
