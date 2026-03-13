import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

function sliceBetween(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  assert(start !== -1, `Missing block start: ${startNeedle}`);
  const end = source.indexOf(endNeedle, start);
  assert(end !== -1, `Missing block end after: ${startNeedle}`);
  return source.slice(start, end);
}

const editorSource = readFileSync(path.resolve(process.cwd(), 'src/editor/index.ts'), 'utf8');
const marksSource = readFileSync(path.resolve(process.cwd(), 'src/editor/plugins/marks.ts'), 'utf8');

const helperBlock = sliceBetween(
  editorSource,
  '  private applyShareMutationSnapshot(',
  '\n  private applyLatestCollabMarksToEditor(): void {',
);

assert(
  helperBlock.includes("this.loadDocument(markdown, { allowShareContentMutation: true });"),
  'Expected share mutation snapshot helper to reload authoritative markdown locally',
);
assert(
  helperBlock.includes('applyRemoteMarks(view, marks, { hydrateAnchors: this.collabCanEdit });'),
  'Expected share mutation snapshot helper to reapply authoritative marks after local reload',
);
assert(
  marksSource.includes("import { shouldPreserveMissingLocalMark } from '../../bridge/marks-preservation.js';"),
  'Expected marks plugin to consult missing-mark preservation rules',
);
assert(
  marksSource.includes('const removedAuthoritativeSuggestionIds = new Set<string>();')
    && marksSource.includes('if (shouldPreserveMissingLocalMark(localMark)) continue;'),
  'Expected applyRemoteMarks to drop non-preservable local suggestions when server marks omit them',
);

console.log('✓ share accept local apply wiring checks');
