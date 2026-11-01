import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/',
  server: {
    proxy: {
      '/login': 'http://127.0.0.1:8000',
      '/alerts': 'http://127.0.0.1:8000',
      '/stats': 'http://127.0.0.1:8000',
      '/config': 'http://127.0.0.1:8000',
      '/organization': 'http://127.0.0.1:8000',
      '/simulate': 'http://127.0.0.1:8000',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: 'index.html',
        login: 'login.html',
        alert: 'alert.html',
      },
    },
  },
});
