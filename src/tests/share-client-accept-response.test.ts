import assert from 'node:assert/strict';

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function run(): Promise<void> {
  const originalFetch = globalThis.fetch;
  const originalWindow = (globalThis as { window?: unknown }).window;

  (globalThis as { window: Record<string, unknown> }).window = {
    location: new URL('https://proof-web-staging.up.railway.app/d/test-doc?token=share-token'),
    __PROOF_CONFIG__: {
      proofClientVersion: '0.31.2',
      proofClientBuild: 'test',
      proofClientProtocol: '3',
    },
  };

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === 'string' ? input : input.toString());
    if (url.pathname === '/api/agent/test-doc/state') {
      return jsonResponse({ revision: 41, updatedAt: '2026-03-06T00:00:01.000Z' });
    }
    if (url.pathname === '/api/agent/test-doc/marks/accept') {
      return jsonResponse({
        success: true,
        marks: { 's-1': { kind: 'replace', status: 'accepted' } },
        markdown: 'After accept',
        content: 'After accept',
      });
    }
    throw new Error(`Unexpected request path: ${url.pathname} (${init?.method ?? 'GET'})`);
  };

  try {
    const { shareClient } = await import('../bridge/share-client.js');
    const result = await shareClient.acceptSuggestion('s-1', 'human:editor');
    assert(result && !('error' in result), 'acceptSuggestion should return a success payload');
    assert.equal(result.success, true, 'acceptSuggestion should report success');
    assert.equal(result.markdown, 'After accept', 'acceptSuggestion should surface authoritative markdown');
    assert.equal(result.content, 'After accept', 'acceptSuggestion should surface authoritative content');
    console.log('share-client-accept-response.test.ts passed');
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow === undefined) {
      delete (globalThis as { window?: unknown }).window;
    } else {
      (globalThis as { window?: unknown }).window = originalWindow;
    }
  }
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
