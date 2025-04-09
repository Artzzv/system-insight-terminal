
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
  },
  plugins: [
    react(),
    mode === 'development' &&
    componentTagger(),
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Properly handle Node.js built-in modules
  build: {
    rollupOptions: {
      external: [
        'child_process', 
        'fs', 
        'os', 
        'path',
        'electron'
      ]
    }
  },
  // Disable ESLint for faster build
  optimizeDeps: {
    exclude: ['electron'],
  },
}));
