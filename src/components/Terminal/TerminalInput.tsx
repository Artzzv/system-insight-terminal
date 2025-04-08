
import React, { useState, useRef, useEffect } from 'react';

interface TerminalInputProps {
  prompt: string;
  value: string;
  onChange: (value: string) => void;
  onSubmit: (command: string) => void;
  autoFocus?: boolean;
  suggestions?: string[];
  history?: string[];
  historyIndex?: number;
  onHistoryNavigation?: (direction: 'up' | 'down') => void;
  onTabCompletion?: () => void;
  disabled?: boolean;
}

const TerminalInput: React.FC<TerminalInputProps> = ({
  prompt,
  value,
  onChange,
  onSubmit,
  autoFocus = true,
  suggestions = [],
  history = [],
  historyIndex,
  onHistoryNavigation,
  onTabCompletion,
  disabled = false,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [filteredSuggestions, setFilteredSuggestions] = useState<string[]>([]);
  const [selectedSuggestion, setSelectedSuggestion] = useState(0);

  useEffect(() => {
    if (autoFocus && inputRef.current) {
      inputRef.current.focus();
    }
  }, [autoFocus]);

  useEffect(() => {
    if (value) {
      const filtered = suggestions.filter(suggestion => 
        suggestion.toLowerCase().startsWith(value.toLowerCase())
      );
      setFilteredSuggestions(filtered);
    } else {
      setFilteredSuggestions([]);
    }
  }, [value, suggestions]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (showSuggestions && selectedSuggestion < filteredSuggestions.length) {
        onChange(filteredSuggestions[selectedSuggestion]);
        setShowSuggestions(false);
      } else {
        onSubmit(value);
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      if (filteredSuggestions.length > 0) {
        onChange(filteredSuggestions[0]);
      } else if (onTabCompletion) {
        onTabCompletion();
      }
    } else if (e.key === 'ArrowUp') {
      if (showSuggestions) {
        e.preventDefault();
        setSelectedSuggestion(prev => Math.max(0, prev - 1));
      } else if (onHistoryNavigation) {
        e.preventDefault();
        onHistoryNavigation('up');
      }
    } else if (e.key === 'ArrowDown') {
      if (showSuggestions) {
        e.preventDefault();
        setSelectedSuggestion(prev => Math.min(filteredSuggestions.length - 1, prev + 1));
      } else if (onHistoryNavigation) {
        e.preventDefault();
        onHistoryNavigation('down');
      }
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  const handleFocus = () => {
    if (filteredSuggestions.length > 0) {
      setShowSuggestions(true);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value);
    if (e.target.value) {
      setShowSuggestions(true);
    } else {
      setShowSuggestions(false);
    }
  };

  return (
    <div className="relative">
      <div className="terminal-input-line">
        <span className="terminal-prompt">{prompt}</span>
        <input
          ref={inputRef}
          type="text"
          className="terminal-input"
          value={value}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          onFocus={handleFocus}
          disabled={disabled}
          autoCapitalize="off"
          spellCheck="false"
          autoComplete="off"
        />
        {!disabled && <span className="terminal-cursor" />}
      </div>
      
      {showSuggestions && filteredSuggestions.length > 0 && (
        <div className="absolute left-0 mt-1 w-full z-10 bg-secondary border border-border rounded-md max-h-48 overflow-y-auto">
          {filteredSuggestions.map((suggestion, index) => (
            <div
              key={suggestion}
              className={`px-2 py-1 cursor-pointer hover:bg-muted ${
                index === selectedSuggestion ? 'bg-muted' : ''
              }`}
              onClick={() => {
                onChange(suggestion);
                setShowSuggestions(false);
                inputRef.current?.focus();
              }}
            >
              {suggestion}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default TerminalInput;
