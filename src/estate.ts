import type { Edge, Principal } from './graph.ts';

/**
 * The lab estate, with every planted escalation path written down.
 *
 * Recall is only measurable because the answers are recorded here first. A
 * reachability tool that finds "some paths" on an estate whose true paths are
 * unknown has told you nothing.
 */

export const PRINCIPALS: readonly Principal[] = [
  { id: 'user:contractor', kind: 'user', account: 'dev' },
  { id: 'user:analyst', kind: 'user', account: 'dev' },
  { id: 'role:dev-deploy', kind: 'role', account: 'dev' },
  { id: 'role:ci-runner', kind: 'role', account: 'dev' },
  { id: 'role:migration', kind: 'role', account: 'prod' },
  { id: 'role:backup', kind: 'role', account: 'prod' },
  { id: 'role:readonly-audit', kind: 'role', account: 'prod' },
  { id: 'service:lambda-etl', kind: 'service', account: 'prod' },
  { id: 'service:lambda-report', kind: 'service', account: 'prod' },
  { id: 'resource:kms-customer', kind: 'resource', account: 'prod' },
  { id: 'resource:rds-customers', kind: 'resource', account: 'prod',
    crownJewel: true },
  { id: 'resource:s3-pii-exports', kind: 'resource', account: 'prod',
    crownJewel: true },
  { id: 'resource:secrets-payments', kind: 'resource', account: 'prod',
    crownJewel: true },
  { id: 'resource:s3-public-assets', kind: 'resource', account: 'prod' },
];

export const EDGES: readonly Edge[] = [
  // --- the long chain: contractor -> ... -> customer database --------------
  { from: 'user:contractor', to: 'role:dev-deploy', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/dev-deploy' },
  { from: 'role:dev-deploy', to: 'role:ci-runner', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/ci-runner' },
  { from: 'role:ci-runner', to: 'role:migration', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/migration (cross-account)' },
  { from: 'role:migration', to: 'resource:rds-customers', kind: 'READ_DATA',
    action: 'rds-db:connect customers' },

  // --- the PassRole chain: deploy -> lambda -> kms -> exports --------------
  { from: 'role:dev-deploy', to: 'service:lambda-etl', kind: 'PASS_ROLE',
    action: 'iam:PassRole -> lambda:UpdateFunctionCode lambda-etl' },
  { from: 'service:lambda-etl', to: 'resource:kms-customer', kind: 'DECRYPT',
    action: 'kms:Decrypt key/customer' },
  { from: 'resource:kms-customer', to: 'resource:s3-pii-exports', kind: 'READ_DATA',
    action: 's3:GetObject pii-exports/*' },
  { from: 'service:lambda-etl', to: 'resource:secrets-payments', kind: 'READ_SECRET',
    action: 'secretsmanager:GetSecretValue payments' },

  // --- second PassRole route through the reporting lambda ------------------
  { from: 'role:ci-runner', to: 'service:lambda-report', kind: 'PASS_ROLE',
    action: 'iam:PassRole -> lambda:UpdateFunctionCode lambda-report' },
  { from: 'service:lambda-report', to: 'resource:s3-pii-exports', kind: 'READ_DATA',
    action: 's3:GetObject pii-exports/*' },

  // --- backup role reaches everything, as backup roles always do -----------
  { from: 'role:ci-runner', to: 'role:backup', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/backup' },
  { from: 'role:backup', to: 'resource:rds-customers', kind: 'READ_DATA',
    action: 'rds:CreateDBSnapshot customers' },
  { from: 'role:backup', to: 'resource:s3-pii-exports', kind: 'READ_DATA',
    action: 's3:GetObject pii-exports/*' },

  // --- a cycle, which is a real misconfiguration and breaks naive traversal -
  { from: 'role:backup', to: 'role:dev-deploy', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/dev-deploy (cycle)' },

  // --- edges that must be PRUNED, not reported -----------------------------
  // Only reachable from inside the corporate VPC.
  { from: 'user:analyst', to: 'role:migration', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/migration',
    conditions: { 'aws:SourceVpc': 'vpc-corp' } },
  // Requires MFA.
  { from: 'user:analyst', to: 'role:backup', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/backup',
    conditions: { 'aws:MultiFactorAuthPresent': 'true' } },
  // Permission boundary on the audit role forbids PassRole entirely.
  { from: 'role:readonly-audit', to: 'service:lambda-etl', kind: 'PASS_ROLE',
    action: 'iam:PassRole -> lambda-etl',
    boundaryAllows: ['READ_DATA'] },

  // --- benign edges, to keep the graph honest ------------------------------
  { from: 'user:analyst', to: 'role:readonly-audit', kind: 'ASSUME_ROLE',
    action: 'sts:AssumeRole role/readonly-audit' },
  { from: 'role:readonly-audit', to: 'resource:s3-public-assets',
    kind: 'READ_DATA', action: 's3:GetObject public-assets/*' },
];

/**
 * GROUND TRUTH: the escalation paths that genuinely exist from
 * `user:contractor`, outside the corporate VPC and without MFA.
 * Recorded as node sequences so recall is exact rather than approximate.
 */
export const PLANTED_PATHS: readonly string[][] = [
  ['user:contractor', 'role:dev-deploy', 'service:lambda-etl',
    'resource:secrets-payments'],
  ['user:contractor', 'role:dev-deploy', 'service:lambda-etl',
    'resource:kms-customer', 'resource:s3-pii-exports'],
  ['user:contractor', 'role:dev-deploy', 'role:ci-runner', 'role:migration',
    'resource:rds-customers'],
  ['user:contractor', 'role:dev-deploy', 'role:ci-runner',
    'service:lambda-report', 'resource:s3-pii-exports'],
  ['user:contractor', 'role:dev-deploy', 'role:ci-runner', 'role:backup',
    'resource:rds-customers'],
  ['user:contractor', 'role:dev-deploy', 'role:ci-runner', 'role:backup',
    'resource:s3-pii-exports'],
];

/** Paths that must NOT be reported for an attacker outside the VPC, no MFA. */
export const MUST_NOT_APPEAR: readonly string[] = [
  'user:analyst', // every onward edge from the analyst is condition-gated
];
