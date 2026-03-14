import { unlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import * as Y from 'yjs';
import { HocuspocusProvider } from '@hocuspocus/provider';
import {
  WebSocket as NodeWebSocket,
  WebSocketServer,
} from 'ws';

if (typeof (globalThis as { WebSocket?: unknown }).WebSocket === 'undefined') {
  (globalThis as { WebSocket?: unknown }).WebSocket = NodeWebSocket;
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs: number,
  label: string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    if (await predicate()) return;
    await sleep(25);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function mustJson<T>(res: Response, label: string): Promise<T> {
  const text = await res.text().catch(() => '');
  if (!res.ok) throw new Error(`${label}: HTTP ${res.status}: ${text.slice(0, 500)}`);
  return JSON.parse(text) as T;
}

function normalizeWsBase(collabWsUrl: string): string {
  const raw = collabWsUrl.replace(/\?slug=.*$/, '');
  try {
    const url = new URL(raw);
    if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
    return url.toString();
  } catch {
    return raw.replace('ws://localhost:', 'ws://127.0.0.1:');
  }
}

function replaceYText(text: Y.Text, value: string): void {
  const current = text.toString();
  if (current.length > 0) text.delete(0, current.length);
  if (value.length > 0) text.insert(0, value);
}

type CreateResponse = {
  slug: string;
  ownerSecret: string;
};

type SuggestResponse = {
  marks?: Record<string, { kind?: string; content?: string }>;
};

type CollabSessionResponse = {
  success: boolean;
  session: {
    collabWsUrl: string;
    slug: string;
    token: string;
    role: string;
  };
};

type AcceptResponse = {
  success?: boolean;
  code?: string;
  error?: string;
  reason?: string;
  collab?: {
    status?: string;
    reason?: string;
    markdownConfirmed?: boolean | null;
    fragmentConfirmed?: boolean | null;
    canonicalConfirmed?: boolean | null;
  };
};

const CLIENT_HEADERS = {
  'X-Proof-Client-Version': '0.31.2',
  'X-Proof-Client-Build': 'tests',
  'X-Proof-Client-Protocol': '3',
};

async function run(): Promise<void> {
  const dbName =
    `proof-marks-accept-stale-markdown-${Date.now()}-`
    + `${Math.random().toString(36).slice(2)}.db`;
  const dbPath = path.join(os.tmpdir(), dbName);
  process.env.DATABASE_PATH = dbPath;
  process.env.COLLAB_EMBEDDED_WS = '1';
  process.env.AGENT_EDIT_COLLAB_STABILITY_MS = '500';
  process.env.AGENT_EDIT_COLLAB_STABILITY_SAMPLE_MS = '50';

  const [{ apiRoutes }, { agentRoutes }, { setupWebSocket }, collab] =
    await Promise.all([
      import('../../server/routes.js'),
      import('../../server/agent-routes.js'),
      import('../../server/ws.js'),
      import('../../server/collab.js'),
    ]);

  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use('/api', apiRoutes);
  app.use('/api/agent', agentRoutes);

  const server = createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });
  setupWebSocket(wss);

  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve()),
  );
  const address = server.address() as AddressInfo;
  const httpBase = `http://127.0.0.1:${address.port}`;

  await collab.startCollabRuntimeEmbedded(address.port);

  const originalMarkdown = 'Hello open source';

  const createRes = await fetch(`${httpBase}/api/documents`, {
    method: 'POST',
    headers: { ...CLIENT_HEADERS, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title: 'Suggestion accept stale markdown fallback regression',
      markdown: originalMarkdown,
      marks: {},
    }),
  });
  const created = await mustJson<CreateResponse>(createRes, 'create');

  const suggestRes = await fetch(
    `${httpBase}/api/agent/${created.slug}/marks/suggest-replace`,
    {
      method: 'POST',
      headers: {
        ...CLIENT_HEADERS,
        'Content-Type': 'application/json',
        'x-share-token': created.ownerSecret,
      },
      body: JSON.stringify({
        quote: 'open source',
        content: 'OSS',
        by: 'ai:test',
      }),
    },
  );
  assert(suggestRes.ok, `Expected suggestion ok, got HTTP ${suggestRes.status}`);
  const suggestPayload = await mustJson<SuggestResponse>(suggestRes, 'suggest');
  const suggestionId = Object.entries(suggestPayload.marks ?? {}).find(
    ([, value]) => value?.kind === 'replace',
  )?.[0] ?? '';
  assert(suggestionId.length > 0, 'Expected suggestion id');

  const collabSessionRes = await fetch(
    `${httpBase}/api/documents/${created.slug}/collab-session`,
    {
      headers: {
        ...CLIENT_HEADERS,
        'x-share-token': created.ownerSecret,
      },
    },
  );
  const collabSession = await mustJson<CollabSessionResponse>(
    collabSessionRes,
    'collab-session',
  );
  assert(collabSession.success === true, 'Expected successful collab session');

  const ydoc = new Y.Doc();
  const provider = new HocuspocusProvider({
    url: normalizeWsBase(collabSession.session.collabWsUrl),
    name: collabSession.session.slug,
    document: ydoc,
    parameters: {
      token: collabSession.session.token,
      role: collabSession.session.role,
    },
    token: collabSession.session.token,
    preserveConnection: false,
    broadcast: false,
  });

  let connected = false;
  let synced = false;
  provider.on('status', (event: { status: string }) => {
    if (event.status === 'connected') connected = true;
  });
  provider.on('synced', (event: { state?: boolean }) => {
    if (event.state !== false) synced = true;
  });

  try {
    await waitFor(
      () => connected && synced,
      10_000,
      'provider connected+synced',
    );

    const markdownText = ydoc.getText('markdown');
    const acceptPromise = fetch(
      `${httpBase}/api/agent/${created.slug}/marks/accept`,
      {
        method: 'POST',
        headers: {
          ...CLIENT_HEADERS,
          'Content-Type': 'application/json',
          'x-share-token': created.ownerSecret,
        },
        body: JSON.stringify({ markId: suggestionId, by: 'human:editor' }),
      },
    );

    await waitFor(
      () => markdownText.toString().includes('OSS'),
      5_000,
      'accepted markdown applied once',
    );

    // Reproduce the live-viewer drift: replay stale markdown text while the
    // accepted fragment remains correct.
    ydoc.transact(() => {
      replaceYText(markdownText, originalMarkdown);
    }, 'stale-markdown-replay');

    const acceptRes = await acceptPromise;
    const acceptText = await acceptRes.text();
    const acceptPayload = JSON.parse(acceptText) as AcceptResponse;
    assert(
      acceptRes.ok,
      `Expected marks/accept to recover after stale markdown replay, got `
        + `HTTP ${acceptRes.status}: ${acceptText.slice(0, 500)}`,
    );
    assert(acceptPayload.success === true, 'Expected accept success');
    assert(
      acceptPayload.collab?.status === 'confirmed',
      `Expected collab confirmed after fallback, got `
        + `${String(acceptPayload.collab?.status)} `
        + `${JSON.stringify(acceptPayload.collab ?? {})}`,
    );

    await waitFor(
      () => markdownText.toString().includes('OSS'),
      5_000,
      'fallback re-applied accepted markdown text',
    );
    assert(
      !markdownText.toString().includes('open source'),
      `Expected stale markdown replay to be repaired, got `
        + `${markdownText.toString()}`,
    );

    const stateRes = await fetch(`${httpBase}/api/agent/${created.slug}/state`, {
      headers: {
        ...CLIENT_HEADERS,
        'x-share-token': created.ownerSecret,
      },
    });
    const state = await mustJson<{ markdown?: string; content?: string }>(
      stateRes,
      'state',
    );
    const markdown = typeof state.markdown === 'string'
      ? state.markdown
      : (state.content || '');
    assert(
      markdown.includes('OSS'),
      'Expected accepted suggestion to persist in canonical markdown',
    );

    console.log(
      '✓ marks/accept uses barrier fallback to repair stale markdown replay',
    );
  } finally {
    try {
      provider.disconnect();
      provider.destroy();
    } catch {
      // ignore
    }
    ydoc.destroy();
    await collab.stopCollabRuntime();
    try {
      wss.close();
    } catch {
      // ignore
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        unlinkSync(`${dbPath}${suffix}`);
      } catch {
        // ignore
      }
    }
  }
}

run().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
