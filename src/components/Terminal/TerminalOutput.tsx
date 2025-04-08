
import React from 'react';

export type OutputType = 'standard' | 'success' | 'error' | 'warning' | 'info' | 'command' | 'prompt';

export interface TerminalOutputLine {
  id: string;
  type: OutputType;
  content: React.ReactNode;
  timestamp?: Date;
}

interface TerminalOutputProps {
  lines: TerminalOutputLine[];
  showTimestamps?: boolean;
}

const TerminalOutput: React.FC<TerminalOutputProps> = ({ lines, showTimestamps = false }) => {
  const getTypeClass = (type: OutputType): string => {
    switch (type) {
      case 'success': return 'terminal-success';
      case 'error': return 'terminal-error';
      case 'warning': return 'terminal-warning';
      case 'info': return 'terminal-info';
      case 'command': return 'terminal-command';
      case 'prompt': return 'terminal-prompt';
      default: return 'terminal-output';
    }
  };

  const formatTimestamp = (date?: Date): string => {
    if (!date) return '';
    return `[${date.toLocaleTimeString()}] `;
  };

  return (
    <div className="font-mono text-sm whitespace-pre-wrap break-words">
      {lines.map((line) => (
        <div key={line.id} className={`${getTypeClass(line.type)} mb-1`}>
          {showTimestamps && line.timestamp && (
            <span className="text-muted-foreground text-xs mr-2">
              {formatTimestamp(line.timestamp)}
            </span>
          )}
          {line.content}
        </div>
      ))}
    </div>
  );
};

export default TerminalOutput;
