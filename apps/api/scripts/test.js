import { spawnSync } from 'node:child_process';
import process from 'node:process';

process.env.NODE_ENV = 'test';

const testFiles = [
  'src/test/security.test.ts',
  'src/test/auth.test.ts',
  'src/test/authIntegration.test.ts',
  'src/test/asyncScan.test.ts',
  'src/test/realMongoConcurrency.test.ts',
  'src/test/orphanCleanup.test.ts',
  'src/test/indexMigration.test.ts',
  'src/test/messageAnalysis.test.ts',
  'src/test/correlation.test.ts',
  'src/test/blockchain.test.ts',
  'src/test/aiExplanation.test.ts',
];

const result = spawnSync('npx', ['tsx', '--test', ...testFiles], {
  stdio: 'inherit',
  shell: true,
  env: process.env,
});

process.exit(result.status || 0);

