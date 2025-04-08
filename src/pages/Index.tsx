
import React from 'react';
import Terminal from '@/components/Terminal/Terminal';

const Index = () => {
  return (
    <div className="min-h-screen bg-terminal-dark p-4 sm:p-6 md:p-8">
      <div className="max-w-7xl mx-auto h-[calc(100vh-4rem)]">
        <Terminal />
      </div>
    </div>
  );
};

export default Index;
