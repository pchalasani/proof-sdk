import { deriveCollabApplied, type CollabStatusLike } from './agent-collab-status.js';

export type MarksAcceptCollabStatus = CollabStatusLike & {
  reason?: string | null;
};

export type MarksAcceptCollabMetadata = {
  collabApplied: boolean;
  collab: {
    status: 'confirmed' | 'pending';
    reason: string;
    markdownConfirmed: boolean | null;
    fragmentConfirmed: boolean | null;
    canonicalConfirmed: boolean | null;
  };
};

const NON_FATAL_MARKS_ACCEPT_REASONS = new Set([
  'live_doc_unavailable',
]);

export function buildMarksAcceptCollabMetadata(
  status: MarksAcceptCollabStatus,
): MarksAcceptCollabMetadata {
  const collabApplied = deriveCollabApplied(status);
  return {
    collabApplied,
    collab: {
      status: collabApplied ? 'confirmed' : 'pending',
      reason: status.reason ?? (collabApplied ? 'confirmed' : 'sync_timeout'),
      markdownConfirmed: status.markdownConfirmed ?? null,
      fragmentConfirmed: status.fragmentConfirmed ?? null,
      canonicalConfirmed: status.canonicalConfirmed ?? null,
    },
  };
}

export function shouldTreatMarksAcceptCollabAsFatal(
  status: MarksAcceptCollabStatus,
): boolean {
  if (deriveCollabApplied(status)) return false;
  if (status.canonicalConfirmed === false) return true;
  return !NON_FATAL_MARKS_ACCEPT_REASONS.has(status.reason ?? '');
}
