import { readFileSync } from 'node:fs';
import path from 'node:path';

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function run(): void {
  const source = readFileSync(
    path.resolve(process.cwd(), 'server/agent-routes.ts'),
    'utf8',
  );

  assert(
    source.includes('const refreshedHash = hashCanonicalDocument(')
      && source.includes('if (refreshedHash !== canonicalExpectedHash) {')
      && source.includes("reason = 'canonical_changed_before_fallback';"),
    'Expected collab fallback to abort when canonical state changes before the barrier retry',
  );

  assert(
    !source.includes('const repaired = updateDocument(slug, targetMarkdown, targetMarks);'),
    'Expected collab fallback to stop rewriting canonical state from a stale target snapshot',
  );

  assert(
    source.includes("markdown: refreshedMarkdown,")
      && source.includes("marks: refreshedMarks,")
      && source.includes("source: `${options.source ?? 'agent'}-fallback`,"),
    'Expected collab fallback to reapply the freshly-read canonical document to live collab',
  );

  console.log('✓ collab fallback no longer rewrites canonical state from stale snapshots');
}

try {
  run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
