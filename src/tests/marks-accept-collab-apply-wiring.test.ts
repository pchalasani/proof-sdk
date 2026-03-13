import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const agentRoutesPath = path.resolve(process.cwd(), 'server', 'agent-routes.ts');
const source = readFileSync(agentRoutesPath, 'utf8');

const acceptRouteMatch = source.match(
  /details: 'suggestion\.accept'[\s\S]*?\{\s*verify:\s*true,[\s\S]*?strictLiveDoc:\s*true,[\s\S]*?\}/m,
);

assert(acceptRouteMatch, 'Expected /marks/accept to call notifyCollabMutation with verification enabled');
assert(
  acceptRouteMatch[0].includes("source: 'marks.accept'"),
  'Expected /marks/accept to use the marks.accept collab source',
);
assert(
  !acceptRouteMatch[0].includes('apply: false'),
  'Expected /marks/accept to reapply canonical markdown into collab after acceptance',
);

console.log('✓ marks/accept collab apply wiring checks');
