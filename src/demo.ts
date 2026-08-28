/**
 * The 60-second artefact: what per-policy review sees, and what the graph sees.
 * Run: `npm run demo`
 */
import {
  createDatabase, load, pathsToCrownJewels, rankRemediations,
} from './graph.ts';
import { PRINCIPALS, EDGES } from './estate.ts';

const EXTERNAL = { sourceVpc: 'vpc-attacker', mfaPresent: false };
const db = createDatabase();
load(db, PRINCIPALS, EDGES, EXTERNAL);

console.log('\n  BLASTGRAPH - IAM as reachability, not as a findings list');
console.log('  ' + '-'.repeat(70));
console.log(`  Estate: ${PRINCIPALS.length} principals, ${EDGES.length} privilege ` +
            `edges, 3 tagged crown jewels.`);
console.log('  Attacker holds user:contractor credentials, off-network, no MFA.\n');

console.log('  What per-policy review reports:');
console.log('    role/dev-deploy   - scoped to dev account, no wildcards  OK');
console.log('    role/ci-runner    - standard CI permissions              OK');
console.log('    role/migration    - DB access, prod, tightly scoped      OK');
console.log('    role/backup       - snapshot + read, as expected         OK');
console.log('    -> 0 findings\n');

const paths = pathsToCrownJewels(db, 'user:contractor');
console.log(`  What reachability reports: ${paths.length} paths to crown jewels\n`);

for (const p of paths.slice(0, 4)) {
  console.log(`  [${p.hops} hops] ${p.target}`);
  for (let i = 0; i < p.actions.length; i++) {
    console.log(`      ${i + 1}. ${p.actions[i]}`);
  }
  console.log();
}
if (paths.length > 4) console.log(`  ... and ${paths.length - 4} more\n`);

// The edges that were correctly NOT reported.
const pruned = db.prepare(
  'SELECT from_id, to_id, pruned_by FROM edge WHERE viable = 0').all() as Array<{
  from_id: string; to_id: string; pruned_by: string;
}>;
console.log('  Edges pruned as non-viable in this context (NOT reported as paths):');
for (const e of pruned) {
  console.log(`    ${e.from_id} -> ${e.to_id}`);
  console.log(`      ${e.pruned_by}`);
}
console.log('\n  Reporting those would be the false positive that gets the tool');
console.log('  uninstalled. The analyst genuinely cannot take them from here.\n');

const ranked = rankRemediations(db, ['user:contractor'], 8, 4);
console.log('  Single-edge removals, ranked by paths eliminated:');
for (const r of ranked) {
  const pct = Math.round((r.pathsEliminated / paths.length) * 100);
  console.log(`    ${String(r.pathsEliminated).padStart(2)}/${paths.length} ` +
              `(${String(pct).padStart(3)}%)  ${r.from} -> ${r.to}`);
  console.log(`               ${r.action}`);
}
console.log("\n  The first row is the attacker's own entry hop - correct, but that");
console.log('  is the incident, not a fix. The rows below it are the structural');
console.log('  changes a platform team can actually make.\n');
db.close();
