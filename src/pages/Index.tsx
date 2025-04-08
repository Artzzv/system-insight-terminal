
import React from 'react';
import Terminal from '@/components/Terminal/Terminal';

const Index = () => {
  return (
    <div className="min-h-screen bg-terminal-dark p-2 sm:p-4 md:p-6">
      <div className="max-w-7xl mx-auto h-[calc(100vh-1rem)] sm:h-[calc(100vh-2rem)] md:h-[calc(100vh-3rem)]">
        <div className="text-center mb-2 sm:mb-4">
          <h1 className="text-white text-xl sm:text-2xl md:text-3xl font-bold">System Insight Terminal</h1>
          <p className="text-muted-foreground text-xs sm:text-sm">Advanced Real-Time System Monitoring & Audit</p>
        </div>
        <Terminal />
      </div>
    </div>
  );
};

export default Index;
