import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api/v2': {
        target: process.env.VITE_CONTROL_PLANE_URL || 'http://127.0.0.1:8787',
        changeOrigin: true,
      },
      '/api/v1': {
        target: process.env.VITE_COLLECTOR_URL || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
