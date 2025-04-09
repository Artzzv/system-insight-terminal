
// Helper function to detect if running in Electron environment
export const isElectron = (): boolean => {
  // Check if running in Electron
  return navigator.userAgent.indexOf('Electron') !== -1;
};
