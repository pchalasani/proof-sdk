import { unlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalizeStoredMarks, type StoredMark } from '../formats/marks.js';
import { stripProofSpanTags } from '../../server/proof-span-strip.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function assertEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error(message ?? `Expected ${String(expected)}, got ${String(actual)}`);
  }
}

function buildRelativeAnchors(
  baseMarkdown: string,
  quote: string,
): { startRel: string; endRel: string; range: { from: number; to: number } } {
  const start = baseMarkdown.indexOf(quote);
  if (start < 0) {
    throw new Error(`Quote not found in base markdown: ${quote}`);
  }
  return {
    startRel: `char:${start}`,
    endRel: `char:${start + quote.length}`,
    range: {
      from: start + 1,
      to: start + 1 + Math.min(100, quote.length),
    },
  };
}

function parseStoredMarks(raw: unknown): Record<string, StoredMark> {
  if (typeof raw !== 'string') return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return canonicalizeStoredMarks(parsed as Record<string, StoredMark>);
  } catch {
    return {};
  }
}

async function run(): Promise<void> {
  const dbName = `proof-marks-accept-stale-unrelated-${Date.now()}-${Math.random().toString(36).slice(2)}.db`;
  const dbPath = path.join(os.tmpdir(), dbName);

  const prevDatabasePath = process.env.DATABASE_PATH;
  const prevProofEnv = process.env.PROOF_ENV;
  const prevNodeEnv = process.env.NODE_ENV;
  const prevDbEnvInit = process.env.PROOF_DB_ENV_INIT;

  process.env.DATABASE_PATH = dbPath;
  process.env.PROOF_ENV = 'development';
  process.env.NODE_ENV = 'development';
  delete process.env.PROOF_DB_ENV_INIT;

  const db = await import('../../server/db.ts');
  const { executeDocumentOperationAsync } = await import('../../server/document-engine.ts');

  try {
    const createdAt = new Date('2026-03-14T21:00:00.000Z').toISOString();
    const slug = `accept-stale-unrelated-${Math.random().toString(36).slice(2, 10)}`;
    const staleCommentId = 'stale-comment';
    const suggestionId = 'accept-target';
    const originalMarkdown = 'Hello world there';
    const currentMarkdown = 'Hello planet there';
    const staleCommentAnchors = buildRelativeAnchors(originalMarkdown, 'world');
    const activeSuggestionAnchors = buildRelativeAnchors(currentMarkdown, 'Hello');

    db.createDocument(
      slug,
      currentMarkdown,
      canonicalizeStoredMarks({
        [staleCommentId]: {
          kind: 'comment',
          by: 'human:test',
          createdAt,
          quote: 'world',
          text: 'Keep this note around',
          threadId: staleCommentId,
          thread: [],
          replies: [],
          resolved: false,
          startRel: staleCommentAnchors.startRel,
          endRel: staleCommentAnchors.endRel,
          range: staleCommentAnchors.range,
        } satisfies StoredMark,
        [suggestionId]: {
          kind: 'replace',
          by: 'ai:test',
          createdAt,
          quote: 'Hello',
          content: 'Hi',
          status: 'pending',
          startRel: activeSuggestionAnchors.startRel,
          endRel: activeSuggestionAnchors.endRel,
          range: activeSuggestionAnchors.range,
        } satisfies StoredMark,
      }),
      'Accept should ignore stale unrelated comment mark',
    );

    const acceptResult = await executeDocumentOperationAsync(
      slug,
      'POST',
      '/marks/accept',
      {
        markId: suggestionId,
        by: 'human:test',
      },
    );
    assertEqual(
      acceptResult.status,
      200,
      `Expected accept to ignore stale unrelated comment mark, got ${acceptResult.status}`,
    );

    const updated = db.getDocumentBySlug(slug);
    assert(Boolean(updated), 'Expected updated document after accept');
    assertEqual(
      stripProofSpanTags(updated?.markdown ?? '').trim(),
      'Hi planet there',
      'Expected target suggestion acceptance to update visible markdown',
    );

    const updatedMarks = parseStoredMarks(updated?.marks);
    assert(
      Boolean(updatedMarks[staleCommentId]),
      'Expected stale unrelated comment mark to remain in stored marks',
    );
    assert(
      !updatedMarks[suggestionId],
      'Expected accepted target suggestion mark to be removed from stored marks',
    );

    console.log(
      '✓ marks/accept ignores stale unrelated marks without dropping them',
    );
  } finally {
    if (prevDatabasePath === undefined) delete process.env.DATABASE_PATH;
    else process.env.DATABASE_PATH = prevDatabasePath;

    if (prevProofEnv === undefined) delete process.env.PROOF_ENV;
    else process.env.PROOF_ENV = prevProofEnv;

    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;

    if (prevDbEnvInit === undefined) delete process.env.PROOF_DB_ENV_INIT;
    else process.env.PROOF_DB_ENV_INIT = prevDbEnvInit;

    for (const suffix of ['', '-wal', '-shm']) {
      try {
        unlinkSync(`${dbPath}${suffix}`);
      } catch {
        // ignore cleanup errors
      }
    }
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
