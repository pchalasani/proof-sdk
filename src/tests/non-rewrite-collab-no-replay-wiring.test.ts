import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const agentRoutesPath = path.resolve(process.cwd(), 'server', 'agent-routes.ts');
const source = readFileSync(agentRoutesPath, 'utf8');

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

assert(
  /else if \(options\?\.apply !== false\)\s*\{\s*await applyCanonicalDocumentToCollab\(/.test(source),
  'Expected notifyCollabMutation to skip canonical collab replay when apply:false is requested',
);

assert(
  source.includes('{ verify: false, apply: false }'),
  'Expected /ops non-rewrite mutations to disable route-level collab replay',
);

const noReplayDetails = [
  'comment.add',
  'suggestion.add.replace',
  'suggestion.add.insert',
  'suggestion.add.delete',
  'suggestion.reject',
  'comment.reply',
  'comment.resolve',
  'comment.unresolve',
];

for (const detail of noReplayDetails) {
  const pattern = new RegExp(
    `details: '${escapeRegex(detail)}'[\\s\\S]{0,240}?\\{ apply: false \\}`,
    'm',
  );
  assert(
    pattern.test(source),
    `Expected ${detail} route to pass apply:false to notifyCollabMutation`,
  );
}

assert(
  /details: `\$\{method\} \$\{path\}`[\s\S]*?\{ apply: false \},/.test(source),
  'Expected the generic mutation passthrough to avoid route-level collab replay',
);

console.log('✓ non-rewrite collab no-replay wiring checks');
