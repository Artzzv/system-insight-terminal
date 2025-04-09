
import React, { useState, useRef, useEffect } from 'react';
import { v4 as uuidv4 } from 'uuid';
import TerminalHeader from './TerminalHeader';
import TerminalOutput, { TerminalOutputLine, OutputType } from './TerminalOutput';
import TerminalInput from './TerminalInput';
import { executeCommand } from '@/utils/commandHandler';
import { Separator } from '@/components/ui/separator';
import { isElectron } from '@/utils/isElectron';

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

  const terminalRef = useRef<HTMLDivElement>(null);

  // Common commands for autocompletion
  const commonCommands = [
    'help', 'clear', 'network-check', 'system-health', 'audit', 
    'show-policies', 'show-defender', 'show-firewall', 'analyze-logs', 'ai-analyze-logs', 
    'event-logs', 'exit', 'ls', 'cd', 'pwd',
    'ifconfig', 'ipconfig', 'ping', 'traceroute', 'netstat', 'arp',
    'ps', 'top', 'htop', 'df', 'du', 'free',
    'cat', 'grep', 'find', 'chmod', 'chown', 'history'
  ];

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
      addOutputLine(`Welcome to Advanced System Insight Terminal v2.0.0`, 'info');
      if (!isElectron()) {
        addOutputLine(`WARNING: Running in browser mode. Please run using Electron app for real system data access.`, 'error');
        addOutputLine(`All system monitoring features require the Electron environment.`, 'warning');
      } else {
        addOutputLine(`Running with full system access. All monitoring features are available.`, 'success');
        addOutputLine(`Log analysis is powered by AI/ML unsupervised learning algorithms.`, 'info');
      }
      addOutputLine(`Type 'help' to see available commands`, 'info');
      addOutputLine('', 'standard');
    }
  }, [outputLines.length]);

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
    </div>
  );
};

export default Terminal;
