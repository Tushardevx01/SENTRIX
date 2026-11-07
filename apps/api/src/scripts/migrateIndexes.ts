import mongoose from 'mongoose';
import { env } from '../utils/config.js';
import { IndexMigrationManager } from '../migrations/indexMigration.js';

async function main() {
  const args = process.argv.slice(2);
  const isDryRun = args.includes('--dry-run') || args.includes('-d');
  const isForce = args.includes('--force');

  console.log(`[SENTRIX Migration] Connecting to MongoDB: ${env.MONGODB_URI.replace(/\/\/.*@/, '//***@')}`);
  await mongoose.connect(env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
  });

  const manager = new IndexMigrationManager();

  if (isDryRun) {
    console.log('[SENTRIX Migration] Mode: DRY RUN (inspection only, zero modifications)');
    const plan = await manager.planMigrations();

    console.log('\n=== MIGRATION INSPECTION REPORT ===');
    console.log(`Migration ID: ${plan.migrationId}`);
    console.log(`Existing valid indexes: ${plan.existingValid.length}`);
    for (const valid of plan.existingValid) {
      console.log(`  ✓ ${valid.collection}.${valid.name}`);
    }

    console.log(`\nPlanned index creations: ${plan.plannedCreations.length}`);
    for (const c of plan.plannedCreations) {
      console.log(`  + [CREATE] ${c.collection}.${c.name}: ${JSON.stringify(c.keys)} (${c.description})`);
    }

    console.log(`\nPlanned obsolete index drops: ${plan.plannedDrops.length}`);
    for (const d of plan.plannedDrops) {
      console.log(`  - [DROP]   ${d.collection}.${d.name}: ${d.reason}`);
    }

    if (plan.duplicatesDetected.length > 0) {
      console.log(`\n⚠️  Duplicate records detected that would require resolution: ${plan.duplicatesDetected.length}`);
      for (const dup of plan.duplicatesDetected) {
        console.log(`  ! ${dup.collection}: ${dup.conflict} (count: ${dup.count})`);
      }
    } else {
      console.log('\n✓ No conflicting duplicate data detected.');
    }

    console.log('\n=== DRY RUN FINISHED (No changes applied) ===');
    await mongoose.disconnect();
    process.exit(0);
  }

  console.log('[SENTRIX Migration] Mode: APPLY (Executing index migrations)');
  try {
    const result = await manager.applyMigrations({ force: isForce });

    console.log('\n=== MIGRATION EXECUTION REPORT ===');
    console.log(`Success: ${result.success}`);
    console.log(`Created Indexes (${result.createdIndexes.length}):`);
    for (const c of result.createdIndexes) {
      console.log(`  + ${c}`);
    }

    console.log(`Dropped Obsolete Indexes (${result.droppedIndexes.length}):`);
    for (const d of result.droppedIndexes) {
      console.log(`  - ${d}`);
    }

    if (result.errors.length > 0) {
      console.error(`\n❌ Migration Errors (${result.errors.length}):`);
      for (const err of result.errors) {
        console.error(`  ! ${err}`);
      }
      await mongoose.disconnect();
      process.exit(1);
    }

    console.log('\n✓ Migration applied and verified successfully.');
    await mongoose.disconnect();
    process.exit(0);
  } catch (error: any) {
    console.error('\n❌ Fatal migration error:', error.message);
    await mongoose.disconnect();
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal initialization error:', err);
  process.exit(1);
});
