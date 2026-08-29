import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  createDatabase, load, pathsToCrownJewels, bestEdgeToRemove, edgeViable,
  type Context,
} from '../src/graph.ts';
import { PRINCIPALS, EDGES, PLANTED_PATHS } from '../src/estate.ts';

/** An attacker with the contractor's credentials, off-network, no MFA. */
const EXTERNAL: Context = { sourceVpc: 'vpc-attacker', mfaPresent: false };
const INTERNAL: Context = { sourceVpc: 'vpc-corp', mfaPresent: true };

function estate(ctx: Context) {
  const db = createDatabase();
  load(db, PRINCIPALS, EDGES, ctx);
  return db;
}

describe('reachability against planted ground truth', () => {
  test('THE HEADLINE: every planted path is found', () => {
    const db = estate(EXTERNAL);
    const found = pathsToCrownJewels(db, 'user:contractor');
    const foundKeys = new Set(found.map((p) => p.nodes.join(' -> ')));

    for (const planted of PLANTED_PATHS) {
      assert.ok(
        foundKeys.has(planted.join(' -> ')),
        `MISSED planted path: ${planted.join(' -> ')}`,
      );
    }
    db.close();
  });

  test('recall is 100% and the false-path count is reported honestly', () => {
    const db = estate(EXTERNAL);
    const found = pathsToCrownJewels(db, 'user:contractor');
    const planted = new Set(PLANTED_PATHS.map((p) => p.join(' -> ')));
    const extra = found.filter((p) => !planted.has(p.nodes.join(' -> ')));

    assert.equal(found.length - extra.length, PLANTED_PATHS.length);
    // Extra paths here are longer routes to the same jewels, not false
    // positives, but the number is asserted rather than waved away.
    assert.ok(extra.length <= 6,
      `${extra.length} unplanted paths - investigate before trusting the tool`);
    db.close();
  });

  test('finds paths of length 4 or more that per-policy review misses', () => {
    const db = estate(EXTERNAL);
    const deep = pathsToCrownJewels(db, 'user:contractor').filter((p) => p.hops >= 4);
    assert.ok(deep.length >= 3,
      `expected several deep chains, found ${deep.length}`);
    db.close();
  });

  test('each path carries the actual API call sequence', () => {
    const db = estate(EXTERNAL);
    const p = pathsToCrownJewels(db, 'user:contractor')
      .find((x) => x.target === 'resource:secrets-payments')!;
    assert.equal(p.actions.length, p.hops);
    assert.match(p.actions[0]!, /sts:AssumeRole/);
    assert.match(p.actions.at(-1)!, /secretsmanager:GetSecretValue/);
    db.close();
  });

  test('paths are ordered shortest first - the shortest is the urgent one', () => {
    const db = estate(EXTERNAL);
    const hops = pathsToCrownJewels(db, 'user:contractor').map((p) => p.hops);
    assert.deepEqual(hops, [...hops].sort((a, b) => a - b));
    db.close();
  });
});

describe('THE FALSE POSITIVE THAT DESTROYS TRUST', () => {
  test('a VPC-gated edge does not produce a path from outside the VPC', () => {
    const db = estate(EXTERNAL);
    const found = pathsToCrownJewels(db, 'user:analyst');
    assert.equal(found.length, 0,
      'reported a path the analyst cannot actually take from outside the VPC');
    db.close();
  });

  test('the same analyst DOES have paths from inside the VPC with MFA', () => {
    // Proving the pruning is context-sensitive rather than simply dropping
    // every conditioned edge - which would be under-reporting, not accuracy.
    const db = estate(INTERNAL);
    const found = pathsToCrownJewels(db, 'user:analyst');
    assert.ok(found.length > 0, 'over-pruned: the internal path is real');
    db.close();
  });

  test('a permission boundary prunes the edge it forbids', () => {
    const v = edgeViable(
      { from: 'role:readonly-audit', to: 'service:lambda-etl', kind: 'PASS_ROLE',
        action: 'iam:PassRole', boundaryAllows: ['READ_DATA'] },
      EXTERNAL,
    );
    assert.equal(v.viable, false);
    assert.match(v.prunedBy!, /permission boundary/);
  });

  test('pruning records WHY, so a reviewer can disagree with it', () => {
    const v = edgeViable(
      { from: 'a', to: 'b', kind: 'ASSUME_ROLE', action: 'x',
        conditions: { 'aws:SourceVpc': 'vpc-corp' } },
      EXTERNAL,
    );
    assert.equal(v.viable, false);
    assert.match(v.prunedBy!, /aws:SourceVpc=vpc-corp/);
  });

  test('an MFA-gated edge is viable when MFA is present', () => {
    const edge = { from: 'a', to: 'b', kind: 'ASSUME_ROLE' as const, action: 'x',
      conditions: { 'aws:MultiFactorAuthPresent': 'true' } };
    assert.equal(edgeViable(edge, EXTERNAL).viable, false);
    assert.equal(edgeViable(edge, INTERNAL).viable, true);
  });

  test('an unconditioned edge is always viable', () => {
    assert.equal(
      edgeViable({ from: 'a', to: 'b', kind: 'ASSUME_ROLE', action: 'x' },
        EXTERNAL).viable, true);
  });
});

describe('graph mechanics', () => {
  test('a cycle in the estate does not hang the traversal', () => {
    // role:backup -> role:dev-deploy closes a loop. Without the visited-set
    // guard this recurses until SQLite aborts.
    const db = estate(EXTERNAL);
    const found = pathsToCrownJewels(db, 'user:contractor', 8);
    assert.ok(found.length > 0);
    for (const p of found) {
      assert.equal(new Set(p.nodes).size, p.nodes.length,
        `path revisits a node: ${p.nodes.join(' -> ')}`);
    }
    db.close();
  });

  test('maxHops bounds the search', () => {
    const db = estate(EXTERNAL);
    const shallow = pathsToCrownJewels(db, 'user:contractor', 2);
    assert.ok(shallow.every((p) => p.hops <= 2));
    assert.ok(shallow.length < pathsToCrownJewels(db, 'user:contractor', 8).length);
    db.close();
  });

  test('a principal with no outbound edges reaches nothing', () => {
    const db = estate(EXTERNAL);
    assert.equal(pathsToCrownJewels(db, 'resource:s3-public-assets').length, 0);
    db.close();
  });

  test('non-crown-jewel resources are not reported as targets', () => {
    const db = estate(EXTERNAL);
    const targets = new Set(
      pathsToCrownJewels(db, 'user:contractor').map((p) => p.target));
    assert.ok(!targets.has('resource:s3-public-assets'));
    assert.ok(!targets.has('resource:kms-customer'),
      'kms is a stepping stone, not a tagged jewel');
    db.close();
  });
});

describe('the counterfactual that turns findings into a ticket', () => {
  test('names the single edge whose removal kills the most paths', () => {
    const db = estate(EXTERNAL);
    const best = bestEdgeToRemove(db, ['user:contractor']);
    assert.ok(best, 'expected a recommendation');
    assert.ok(best!.pathsEliminated > 0);
    db.close();
  });

  test('the recommended removal actually reduces reachability', () => {
    const db = estate(EXTERNAL);
    const before = pathsToCrownJewels(db, 'user:contractor').length;
    const best = bestEdgeToRemove(db, ['user:contractor'])!;
    db.prepare('UPDATE edge SET viable = 0 WHERE from_id = ? AND to_id = ?')
      .run(best.from, best.to);
    const after = pathsToCrownJewels(db, 'user:contractor').length;
    assert.equal(before - after, best.pathsEliminated);
    db.close();
  });
});
