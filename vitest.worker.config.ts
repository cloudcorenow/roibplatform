import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'miniflare',
    environmentOptions: {
      bindings: {
        DB: 'TEST_DB',
        KV: 'TEST_KV'
      },
      kvNamespaces: ['TEST_KV'],
      d1Databases: ['TEST_DB']
    },
    setupFiles: ['./src/test/worker-setup.ts'],
  },
});