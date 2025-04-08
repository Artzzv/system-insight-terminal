
import React from 'react';
import { Circle, Maximize2, Minus, X } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface TerminalHeaderProps {
  title: string;
  onMinimize?: () => void;
  onMaximize?: () => void;
  onClose?: () => void;
}

const TerminalHeader: React.FC<TerminalHeaderProps> = ({
  title,
  onMinimize,
  onMaximize,
  onClose,
}) => {
  return (
    <div className="terminal-header">
      <div className="flex space-x-2 mr-4">
        <Circle className="h-3 w-3 text-terminal-error cursor-pointer" onClick={onClose} />
        <Circle className="h-3 w-3 text-terminal-warning cursor-pointer" onClick={onMinimize} />
        <Circle className="h-3 w-3 text-terminal-success cursor-pointer" onClick={onMaximize} />
      </div>
      <div className="flex-1 text-center text-sm font-medium">{title}</div>
      <div className="flex space-x-2">
        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onMinimize}>
          <Minus className="h-3 w-3" />
        </Button>
        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onMaximize}>
          <Maximize2 className="h-3 w-3" />
        </Button>
        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onClose}>
          <X className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
};

export default TerminalHeader;
