import { unlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildTextIndex, mapTextOffsetsToRange, resolveQuoteRange } from '../editor/utils/text-range.js';
import { getHeadlessMilkdownParser, parseMarkdownWithHtmlFallback } from '../../server/milkdown-headless.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function assertEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error(message ?? `Expected ${String(expected)}, got ${String(actual)}`);
  }
}

async function buildExpectedAnchors(
  markdown: string,
  quote: string,
): Promise<{ startRel: string; endRel: string; range: { from: number; to: number } } | null> {
  const parser = await getHeadlessMilkdownParser();
  const parsed = parseMarkdownWithHtmlFallback(parser, markdown);
  if (!parsed.doc) return null;
  const range = resolveQuoteRange(parsed.doc, quote);
  if (!range) return null;
  const index = buildTextIndex(parsed.doc);
  if (!index) return null;

  let startOffset = -1;
  let endOffset = -1;
  for (let i = 0; i < index.positions.length; i += 1) {
    const pos = index.positions[i];
    if (typeof pos !== 'number') continue;
    if (startOffset < 0 && pos >= range.from) {
      startOffset = i;
    }
    if (pos < range.to) {
      endOffset = i + 1;
    }
  }

  if (startOffset < 0 || endOffset <= startOffset) return null;
  const mapped = mapTextOffsetsToRange(index, startOffset, endOffset);
  if (!mapped || mapped.from !== range.from || mapped.to !== range.to) return null;
  return {
    startRel: `char:${startOffset}`,
    endRel: `char:${endOffset}`,
    range,
  };
}

async function run(): Promise<void> {
  const dbName =
    `proof-async-suggestion-anchor-${Date.now()}-`
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
  const { executeDocumentOperationAsync } = await import(
    '../../server/document-engine.ts'
  );

  try {
    const htmlSlug = `async-anchor-html-${Math.random().toString(36).slice(2, 10)}`;
    const htmlMarkdown = '<p>foo</p><p>bar</p>';
    db.createDocument(htmlSlug, htmlMarkdown, {}, 'Async suggestion anchor model');

    const expectedAnchors = await buildExpectedAnchors(htmlMarkdown, 'bar');
    assert(expectedAnchors, 'Expected parsed anchor model for unique HTML quote');

    const addUnique = await executeDocumentOperationAsync(
      htmlSlug,
      'POST',
      '/marks/suggest-replace',
      {
        quote: 'bar',
        content: 'baz',
        by: 'ai:test',
      },
    );
    assertEqual(
      addUnique.status,
      200,
      `Expected unique quote suggestion.add to succeed, got ${addUnique.status}`,
    );
    const uniqueMark = Object.values(
      (addUnique.body.marks ?? {}) as Record<
        string,
        { kind?: string; startRel?: string; endRel?: string; range?: { from: number; to: number } }
      >,
    ).find((mark) => mark?.kind === 'replace');
    assert(uniqueMark, 'Expected stored suggestion mark for unique quote');
    assertEqual(
      uniqueMark.startRel,
      expectedAnchors.startRel,
      'Expected async suggestion.add to store startRel in parsed-document coordinates',
    );
    assertEqual(
      uniqueMark.endRel,
      expectedAnchors.endRel,
      'Expected async suggestion.add to store endRel in parsed-document coordinates',
    );
    assertEqual(
      JSON.stringify(uniqueMark.range),
      JSON.stringify(expectedAnchors.range),
      'Expected async suggestion.add to persist parsed-document range coordinates',
    );

    const uniqueMarkId = Object.entries(
      (addUnique.body.marks ?? {}) as Record<string, { kind?: string }>,
    ).find(([, mark]) => mark?.kind === 'replace')?.[0];
    assert(typeof uniqueMarkId === 'string' && uniqueMarkId.length > 0,
      'Expected unique quote suggestion id');

    const acceptUnique = await executeDocumentOperationAsync(
      htmlSlug,
      'POST',
      '/marks/accept',
      {
        markId: uniqueMarkId,
        by: 'human:test',
      },
    );
    assertEqual(
      acceptUnique.status,
      200,
      `Expected accept after unique async suggestion.add to succeed, got ${acceptUnique.status}`,
    );

    const duplicateSlug = `async-anchor-dup-${Math.random().toString(36).slice(2, 10)}`;
    const duplicateMarkdown = '<p>bar</p><p>bar</p>';
    db.createDocument(duplicateSlug, duplicateMarkdown, {}, 'Async duplicate quote guard');

    const addDuplicate = await executeDocumentOperationAsync(
      duplicateSlug,
      'POST',
      '/marks/suggest-replace',
      {
        quote: 'bar',
        content: 'baz',
        by: 'ai:test',
      },
    );
    assertEqual(
      addDuplicate.status,
      409,
      `Expected duplicate quote suggestion.add to fail fast, got ${addDuplicate.status}`,
    );
    assertEqual(
      addDuplicate.body.code,
      'ANCHOR_NOT_FOUND',
      'Expected duplicate quote suggestion.add to reject ambiguous anchor creation',
    );

    console.log(
      '✓ async suggestion.add stores parsed-model anchors and rejects ambiguous duplicates',
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
