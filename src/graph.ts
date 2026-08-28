import { DatabaseSync } from 'node:sqlite';

/**
 * Cloud IAM as a reachability problem.
 *
 * Per-policy review asks "is this role over-permissive?" and every role
 * individually answers no. Meanwhile the deploy role can assume the migration
 * role, which can pass the backup role to a Lambda, which can read the KMS key
 * that decrypts the customer database. Four hops, every one of them signed off,
 * and no policy reviewer was ever shown the chain.
 *
 * So the estate is modelled as a directed graph of privilege edges and the
 * question becomes transitive reachability to tagged crown jewels. The answer
 * is a PATH - the actual sequence of API calls an attacker would make - not a
 * findings count, because a path is something a team can act on.
 *
 * The reachability itself is a recursive CTE. That is deliberate: it is
 * declarative, it is fast, and it is far easier to defend in review than three
 * hundred lines of hand-rolled graph traversal.
 */

export type EdgeKind =
  | 'ASSUME_ROLE'
  | 'PASS_ROLE'
  | 'ATTACH_POLICY'
  | 'UPDATE_FUNCTION_CODE'
  | 'READ_SECRET'
  | 'DECRYPT'
  | 'READ_DATA';

export interface Principal {
  readonly id: string;
  readonly kind: 'user' | 'role' | 'service' | 'resource';
  readonly account: string;
  /** Crown jewels are tagged. Everything else is a stepping stone. */
  readonly crownJewel?: boolean;
}

export interface Edge {
  readonly from: string;
  readonly to: string;
  readonly kind: EdgeKind;
  /** The API call an attacker would actually make. */
  readonly action: string;
  /** Condition keys on the granting statement. */
  readonly conditions?: Readonly<Record<string, string>>;
  /** A permission boundary on the SOURCE principal, if any. */
  readonly boundaryAllows?: readonly EdgeKind[];
}

export interface Context {
  /** Where the attacker is coming from. Prunes edges gated on source IP/VPC. */
  readonly sourceVpc?: string;
  readonly mfaPresent?: boolean;
}

export function createDatabase(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec(`
CREATE TABLE principal (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,
  account     TEXT NOT NULL,
  crown_jewel INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE edge (
  from_id   TEXT NOT NULL REFERENCES principal(id),
  to_id     TEXT NOT NULL REFERENCES principal(id),
  kind      TEXT NOT NULL,
  action    TEXT NOT NULL,
  viable    INTEGER NOT NULL DEFAULT 1,
  pruned_by TEXT
);
CREATE INDEX idx_edge_from ON edge(from_id);
`);
  return db;
}

/**
 * Decide whether an edge is actually traversable in this context.
 *
 * Getting this wrong in either direction destroys the tool. Ignore conditions
 * and you report paths that cannot happen, the team burns a week disproving
 * them, and they stop reading the output. Over-prune and you miss the real
 * path, which is worse.
 */
export function edgeViable(
  edge: Edge, ctx: Context,
): { viable: boolean; prunedBy?: string } {
  // A permission boundary caps what the source principal can do, no matter
  // what its identity policy grants.
  if (edge.boundaryAllows && !edge.boundaryAllows.includes(edge.kind)) {
    return { viable: false, prunedBy: `permission boundary excludes ${edge.kind}` };
  }
  const c = edge.conditions ?? {};

  if (c['aws:SourceVpc'] !== undefined && c['aws:SourceVpc'] !== ctx.sourceVpc) {
    return {
      viable: false,
      prunedBy: `requires aws:SourceVpc=${c['aws:SourceVpc']}`,
    };
  }
  if (c['aws:MultiFactorAuthPresent'] === 'true' && !ctx.mfaPresent) {
    return { viable: false, prunedBy: 'requires MFA' };
  }
  return { viable: true };
}

export function load(
  db: DatabaseSync, principals: readonly Principal[], edges: readonly Edge[],
  ctx: Context,
): void {
  const p = db.prepare(
    'INSERT INTO principal (id, kind, account, crown_jewel) VALUES (?, ?, ?, ?)');
  for (const x of principals) {
    p.run(x.id, x.kind, x.account, x.crownJewel ? 1 : 0);
  }
  const e = db.prepare(
    `INSERT INTO edge (from_id, to_id, kind, action, viable, pruned_by)
     VALUES (?, ?, ?, ?, ?, ?)`);
  for (const x of edges) {
    const v = edgeViable(x, ctx);
    e.run(x.from, x.to, x.kind, x.action, v.viable ? 1 : 0, v.prunedBy ?? null);
  }
}

export interface Path {
  readonly target: string;
  readonly hops: number;
  readonly nodes: readonly string[];
  readonly actions: readonly string[];
}

/**
 * Transitive reachability from `start` to every tagged crown jewel.
 *
 * The visited-set guard is not optional: IAM graphs contain cycles (role A
 * assumes B, B assumes A is a genuinely common misconfiguration) and without
 * it this recurses until SQLite gives up.
 */
export function pathsToCrownJewels(
  db: DatabaseSync, start: string, maxHops = 8,
): Path[] {
  const rows = db.prepare(`
WITH RECURSIVE reach(node, path, actions, hops) AS (
  SELECT ?, ?, '', 0
  UNION ALL
  SELECT e.to_id,
         r.path || ' -> ' || e.to_id,
         CASE WHEN r.actions = '' THEN e.action
              ELSE r.actions || ' | ' || e.action END,
         r.hops + 1
    FROM reach r
    JOIN edge e ON e.from_id = r.node
   WHERE e.viable = 1
     AND r.hops < ?
     -- cycle guard: never revisit a node already on this path
     AND instr(r.path || ' -> ', e.to_id || ' -> ') = 0
)
SELECT r.node AS target, r.path, r.actions, r.hops
  FROM reach r
  JOIN principal p ON p.id = r.node
 WHERE p.crown_jewel = 1 AND r.hops > 0
 ORDER BY r.hops ASC, r.node ASC
`).all(start, start, maxHops) as Array<{
    target: string; path: string; actions: string; hops: number;
  }>;

  const seen = new Set<string>();
  const out: Path[] = [];
  for (const r of rows) {
    if (seen.has(r.path)) continue;
    seen.add(r.path);
    out.push({
      target: r.target,
      hops: r.hops,
      nodes: r.path.split(' -> '),
      actions: r.actions ? r.actions.split(' | ') : [],
    });
  }
  return out;
}

/**
 * The counterfactual: which single edge removal eliminates the most paths?
 *
 * This is what turns a findings list into a remediation plan. "You have 18
 * escalation paths" is a problem statement; "removing one PassRole grant kills
 * 11 of them" is a ticket.
 */
export interface Remediation {
  from: string;
  to: string;
  action: string;
  pathsEliminated: number;
}

/**
 * Rank every removable edge by how many paths it eliminates.
 *
 * Returning only the single best edge tends to return the attacker's own entry
 * hop, which is both correct and useless - "revoke the contractor's access" is
 * not a finding, it is the incident. The ranked list is what surfaces the
 * structural fixes a platform team can actually make.
 */
export function rankRemediations(
  db: DatabaseSync, starts: readonly string[], maxHops = 8, limit = 5,
): Remediation[] {
  const baseline = starts.flatMap((s) => pathsToCrownJewels(db, s, maxHops)).length;
  const edges = db.prepare(
    'SELECT rowid, from_id, to_id, action FROM edge WHERE viable = 1').all() as
    Array<{ rowid: number; from_id: string; to_id: string; action: string }>;

  const disable = db.prepare('UPDATE edge SET viable = 0 WHERE rowid = ?');
  const restore = db.prepare('UPDATE edge SET viable = 1 WHERE rowid = ?');
  const out: Remediation[] = [];

  for (const e of edges) {
    disable.run(e.rowid);
    const after = starts.flatMap((s) => pathsToCrownJewels(db, s, maxHops)).length;
    restore.run(e.rowid);
    out.push({
      from: e.from_id, to: e.to_id, action: e.action,
      pathsEliminated: baseline - after,
    });
  }
  return out
    .filter((r) => r.pathsEliminated > 0)
    .sort((a, b) => b.pathsEliminated - a.pathsEliminated)
    .slice(0, limit);
}

export function bestEdgeToRemove(
  db: DatabaseSync, starts: readonly string[], maxHops = 8,
): { from: string; to: string; action: string; pathsEliminated: number } | null {
  const baseline = starts.flatMap((s) => pathsToCrownJewels(db, s, maxHops)).length;
  const edges = db.prepare(
    'SELECT rowid, from_id, to_id, action FROM edge WHERE viable = 1').all() as
    Array<{ rowid: number; from_id: string; to_id: string; action: string }>;

  let best: { from: string; to: string; action: string; pathsEliminated: number } | null
    = null;
  const disable = db.prepare('UPDATE edge SET viable = 0 WHERE rowid = ?');
  const restore = db.prepare('UPDATE edge SET viable = 1 WHERE rowid = ?');

  for (const e of edges) {
    disable.run(e.rowid);
    const after = starts.flatMap((s) => pathsToCrownJewels(db, s, maxHops)).length;
    restore.run(e.rowid);
    const eliminated = baseline - after;
    if (!best || eliminated > best.pathsEliminated) {
      best = {
        from: e.from_id, to: e.to_id, action: e.action, pathsEliminated: eliminated,
      };
    }
  }
  return best;
}
