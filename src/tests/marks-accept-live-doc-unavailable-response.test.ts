import {
  buildMarksAcceptCollabMetadata,
  shouldTreatMarksAcceptCollabAsFatal,
} from '../../server/marks-accept-collab.ts';

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function run(): void {
  const liveDocUnavailable = {
    confirmed: false,
    reason: 'live_doc_unavailable',
    markdownConfirmed: false,
    fragmentConfirmed: false,
    canonicalConfirmed: true,
  };

  const pendingMetadata = buildMarksAcceptCollabMetadata(liveDocUnavailable);
  assert(
    pendingMetadata.collabApplied === false,
    'Expected live_doc_unavailable to report collabApplied=false',
  );
  assert(
    pendingMetadata.collab.status === 'pending',
    `Expected pending collab status, got ${pendingMetadata.collab.status}`,
  );
  assert(
    pendingMetadata.collab.reason === 'live_doc_unavailable',
    `Expected live_doc_unavailable reason, got ${pendingMetadata.collab.reason}`,
  );
  assert(
    shouldTreatMarksAcceptCollabAsFatal(liveDocUnavailable) === false,
    'Expected live_doc_unavailable to remain a successful marks/accept response',
  );

  const stabilityRegressed = {
    confirmed: false,
    reason: 'stability_regressed',
    markdownConfirmed: false,
    fragmentConfirmed: true,
    canonicalConfirmed: true,
  };
  assert(
    shouldTreatMarksAcceptCollabAsFatal(stabilityRegressed) === true,
    'Expected stability_regressed to remain a fatal marks/accept collab failure',
  );

  const canonicalFailureThenLiveDocUnavailable = {
    confirmed: false,
    reason: 'live_doc_unavailable',
    markdownConfirmed: false,
    fragmentConfirmed: false,
    canonicalConfirmed: false,
  };
  assert(
    shouldTreatMarksAcceptCollabAsFatal(canonicalFailureThenLiveDocUnavailable)
      === true,
    'Expected canonical convergence failures to stay fatal even if the final reason is live_doc_unavailable',
  );

  console.log('✓ marks/accept treats live_doc_unavailable as pending success');
}

run();
