import { migrationManager } from './migrate';

async function main(): Promise<void> {
  const steps = parseInt(process.argv[2] || '1', 10);
  
  try {
    await migrationManager.rollback(steps);
  } catch (error) {
    console.error('Rollback failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}