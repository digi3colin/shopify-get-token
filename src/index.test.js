import { describe, it, expect, vi, beforeEach } from 'vitest';
import worker from './index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal (unsigned) JWT string whose payload is the given object.
 */
function makeIdToken(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const body = btoa(JSON.stringify(payload))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${header}.${body}.fakesignature`;
}

/**
 * Simulate a Shopify token-exchange API response.
 */
function mockShopifyResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const VALID_PAYLOAD = {
  iss: 'https://test-store.myshopify.com/admin',
  dest: 'https://test-store.myshopify.com',
  aud: 'test-client-id',
  sub: '1',
  exp: 9999999999,
  nbf: 1700000000,
  iat: 1700000000,
  jti: 'abc123',
  sid: 'session-id',
};

const VALID_TOKEN = makeIdToken(VALID_PAYLOAD);
const APP_SECRET = 'my-app-secret';

/**
 * Create a Request object for the worker.
 */
function makeRequest(params = {}) {
  const url = new URL('https://app-domain.com/');
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  return new Request(url.toString());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('shopify-get-token worker', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  // --- Parameter validation ------------------------------------------------

  it('returns 400 when `s` (app secret) is missing', async () => {
    const req = makeRequest({ id_token: VALID_TOKEN });
    const res = await worker.fetch(req);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('Missing');
    expect(text).toContain('s');
  });

  it('returns 400 when `id_token` is missing', async () => {
    const req = makeRequest({ s: APP_SECRET });
    const res = await worker.fetch(req);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('Missing');
    expect(text).toContain('id_token');
  });

  it('returns 400 when `id_token` is not a valid JWT', async () => {
    const req = makeRequest({ s: APP_SECRET, id_token: 'not.a.valid.jwt.format.extra' });
    const res = await worker.fetch(req);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('Invalid');
  });

  it('returns 400 when JWT payload is missing `dest` claim', async () => {
    const token = makeIdToken({ aud: 'client-id' }); // no dest
    const req = makeRequest({ s: APP_SECRET, id_token: token });
    const res = await worker.fetch(req);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('Invalid');
    expect(text).toContain('dest');
  });

  it('returns 400 when JWT payload is missing `aud` claim', async () => {
    const token = makeIdToken({ dest: 'https://test-store.myshopify.com' }); // no aud
    const req = makeRequest({ s: APP_SECRET, id_token: token });
    const res = await worker.fetch(req);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('Invalid');
    expect(text).toContain('aud');
  });

  // --- Successful exchange --------------------------------------------------

  it('exchanges the token and returns HTML with the access token on success', async () => {
    const shopifyData = { access_token: 'shpat_abc123', scope: 'read_products' };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockShopifyResponse(shopifyData, 200)),
    );

    const req = makeRequest({ s: APP_SECRET, id_token: VALID_TOKEN });
    const res = await worker.fetch(req);

    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('shpat_abc123');
    expect(text).toContain('test-store.myshopify.com');
    expect(text).toContain('test-client-id');
  });

  it('POSTs to the correct Shopify endpoint with expected body', async () => {
    const shopifyData = { access_token: 'shpat_xyz' };
    const mockFetch = vi.fn().mockResolvedValue(mockShopifyResponse(shopifyData));
    vi.stubGlobal('fetch', mockFetch);

    const req = makeRequest({ s: APP_SECRET, id_token: VALID_TOKEN });
    await worker.fetch(req);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe('https://test-store.myshopify.com/admin/oauth/access_token');
    expect(options.method).toBe('POST');

    const body = JSON.parse(options.body);
    expect(body.client_id).toBe('test-client-id');
    expect(body.client_secret).toBe(APP_SECRET);
    expect(body.subject_token).toBe(VALID_TOKEN);
    expect(body.grant_type).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(body.subject_token_type).toBe('urn:ietf:params:oauth:token-type:id_token');
    expect(body.requested_token_type).toBe(
      'urn:shopify:params:oauth:token-type:offline-access-token',
    );
  });

  it('accepts aud as an array and uses the first element as client_id', async () => {
    const token = makeIdToken({
      ...VALID_PAYLOAD,
      aud: ['array-client-id', 'other-value'],
    });
    const shopifyData = { access_token: 'shpat_arr' };
    const mockFetch = vi.fn().mockResolvedValue(mockShopifyResponse(shopifyData));
    vi.stubGlobal('fetch', mockFetch);

    const req = makeRequest({ s: APP_SECRET, id_token: token });
    const res = await worker.fetch(req);

    expect(res.status).toBe(200);
    const [, options] = mockFetch.mock.calls[0];
    const body = JSON.parse(options.body);
    expect(body.client_id).toBe('array-client-id');
  });

  // --- Shopify error responses ----------------------------------------------

  it('returns Shopify error status and error JSON in HTML when exchange fails', async () => {
    const shopifyError = { error: 'invalid_client', error_description: 'Bad credentials' };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockShopifyResponse(shopifyError, 401)),
    );

    const req = makeRequest({ s: APP_SECRET, id_token: VALID_TOKEN });
    const res = await worker.fetch(req);

    expect(res.status).toBe(401);
    const text = await res.text();
    expect(text).toContain('invalid_client');
    expect(text).toContain('401');
  });

  it('returns 502 when the Shopify fetch itself throws a network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network failure')),
    );

    const req = makeRequest({ s: APP_SECRET, id_token: VALID_TOKEN });
    const res = await worker.fetch(req);

    expect(res.status).toBe(502);
    const text = await res.text();
    expect(text).toContain('Network failure');
  });

  // --- HTML output ---------------------------------------------------------

  it('returns Content-Type text/html for all responses', async () => {
    // Missing params path
    const res = await worker.fetch(makeRequest({}));
    expect(res.headers.get('Content-Type')).toContain('text/html');
  });

  it('escapes HTML special characters in Shopify response data', async () => {
    const shopifyData = { error: '<script>alert(1)</script>' };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockShopifyResponse(shopifyData, 400)),
    );

    const req = makeRequest({ s: APP_SECRET, id_token: VALID_TOKEN });
    const res = await worker.fetch(req);
    const text = await res.text();
    // The raw <script> tag must NOT appear unescaped in the output
    expect(text).not.toContain('<script>alert(1)</script>');
    expect(text).toContain('&lt;script&gt;');
  });
});
