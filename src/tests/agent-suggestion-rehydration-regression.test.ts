import { unlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalizeStoredMarks, type StoredMark } from '../formats/marks.js';
import { stripAllProofSpanTags } from '../../server/proof-span-strip.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function assertEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error(message ?? `Expected ${String(expected)}, got ${String(actual)}`);
  }
}

async function run(): Promise<void> {
  const dbName =
    `proof-agent-suggestion-rehydrate-${Date.now()}-`
    + `${Math.random().toString(36).slice(2)}.db`;
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
  const { executeDocumentOperation, executeDocumentOperationAsync } = await import(
    '../../server/document-engine.ts'
  );

  try {
    const slug = `agent-rehydrate-${Math.random().toString(36).slice(2, 10)}`;
    const createdAt = new Date('2026-03-13T20:00:00.000Z').toISOString();
    const commentId = 'existing-comment';
    const markdown = [
      `<span data-proof="comment" data-id="${commentId}" data-by="human:test">`,
      'Hello   world',
      '</span>',
      '',
      'Hello world',
    ].join('\n\n');
    const marks = canonicalizeStoredMarks({
      [commentId]: {
        kind: 'comment',
        by: 'human:test',
        createdAt,
        quote: 'Hello world',
        text: 'Comment created in the browser',
        threadId: commentId,
        thread: [],
        replies: [],
        resolved: false,
        startRel: 'char:0',
        endRel: 'char:13',
        range: { from: 1, to: 14 },
      } satisfies StoredMark,
    });
    db.createDocument(slug, markdown, marks, 'Agent rehydration regression');

    const addResult = executeDocumentOperation(
      slug,
      'POST',
      '/marks/suggest-replace',
      {
        quote: 'Hello world',
        content: 'Hi there',
        by: 'ai:test',
      },
    );
    assertEqual(
      addResult.status,
      200,
      `Expected suggestion.add to succeed, got ${addResult.status}`,
    );
    const suggestionId = Object.entries(
      (addResult.body.marks ?? {}) as Record<string, { kind?: string }>,
    ).find(([, mark]) => mark?.kind === 'replace')?.[0];
    assert(typeof suggestionId === 'string' && suggestionId.length > 0,
      'Expected pending suggestion id');

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
      `Expected marks/accept to succeed for agent-posted suggestion, got `
        + `${acceptResult.status} ${JSON.stringify(acceptResult.body)}`,
    );

    const acceptedDoc = db.getDocumentBySlug(slug);
    assert(acceptedDoc, 'Expected accepted document row');
    assertEqual(
      stripAllProofSpanTags(acceptedDoc.markdown).trim(),
      'Hello   world\n\nHi there',
      'Expected accept to preserve the commented occurrence and replace the anchored duplicate quote',
    );
    assert(
      acceptedDoc.markdown.includes(`data-id="${commentId}"`),
      'Expected accept to preserve the existing comment wrapper',
    );

    console.log(
      '✓ agent-posted suggestions rehydrate against browser comment spans',
    );
  } finally {
    try {
      unlinkSync(dbPath);
    } catch {
      // Ignore cleanup failures for temp DBs.
    }
    for (const suffix of ['-wal', '-shm']) {
      try {
        unlinkSync(`${dbPath}${suffix}`);
      } catch {
        // Ignore cleanup failures for temp DBs.
      }
    }

    process.env.DATABASE_PATH = prevDatabasePath;
    process.env.PROOF_ENV = prevProofEnv;
    process.env.NODE_ENV = prevNodeEnv;
    if (prevDbEnvInit === undefined) {
      delete process.env.PROOF_DB_ENV_INIT;
    } else {
      process.env.PROOF_DB_ENV_INIT = prevDbEnvInit;
    }
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
