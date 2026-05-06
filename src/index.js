/**
 * Cloudflare Worker – Shopify Admin API Token Exchange
 *
 * App URL format: https://app-domain.com?s=APP_SECRET
 *
 * Shopify appends the signed session token to the URL as `id_token`.
 * The worker decodes the JWT, extracts the app client-ID from `aud` and
 * the shop domain from `dest`, then exchanges the token for an offline
 * Admin API access token via Shopify's OAuth token-exchange grant.
 */

const HTML_TEMPLATE = (title, body) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: monospace; padding: 2rem; background: #f5f5f5; }
    h1   { color: #333; }
    pre  { background: #fff; border: 1px solid #ddd; padding: 1rem; border-radius: 4px; white-space: pre-wrap; word-break: break-all; }
    .error { color: #c00; }
  </style>
</head>
<body>${body}</body>
</html>`;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Decode a JWT payload without verifying the signature.
 * Returns the parsed payload object.
 * @param {string} token
 * @returns {object}
 */
function decodeJwtPayload(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: expected three dot-separated parts');
  }
  // Base64url → Base64 → binary string → JSON
  const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const json = atob(base64);
  return JSON.parse(json);
}

/**
 * Exchange a Shopify session id_token for an offline Admin API access token.
 *
 * @param {string} shopDomain  e.g. "https://my-store.myshopify.com"
 * @param {string} clientId    App API key (from JWT `aud` claim)
 * @param {string} clientSecret App API secret (provided by caller)
 * @param {string} idToken     The raw JWT string
 * @returns {Promise<{status: number, data: object}>}
 */
async function exchangeToken(shopDomain, clientId, clientSecret, idToken) {
  const endpoint = `${shopDomain.replace(/\/$/, '')}/admin/oauth/access_token`;
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: idToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      requested_token_type:
        'urn:shopify:params:oauth:token-type:offline-access-token',
    }),
  });
  const data = await response.json();
  return { status: response.status, data };
}

function htmlResponse(title, body, status = 200) {
  return new Response(HTML_TEMPLATE(title, body), {
    status,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const secret = url.searchParams.get('s');
    const idToken = url.searchParams.get('id_token');

    // Validate required parameters
    if (!secret) {
      return htmlResponse(
        'Missing Parameter',
        '<h1 class="error">Error</h1><p>Missing required query parameter: <code>s</code> (app secret).</p>',
        400,
      );
    }
    if (!idToken) {
      return htmlResponse(
        'Missing Parameter',
        '<h1 class="error">Error</h1><p>Missing required query parameter: <code>id_token</code>.</p>',
        400,
      );
    }

    let payload;
    try {
      payload = decodeJwtPayload(idToken);
    } catch (err) {
      return htmlResponse(
        'Invalid Token',
        `<h1 class="error">Error – Invalid id_token</h1><p>${escapeHtml(err.message)}</p>`,
        400,
      );
    }

    // `aud` may be a string or an array; take the first element
    const clientId = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
    // `dest` contains the shop origin, e.g. "https://my-store.myshopify.com"
    const shopDomain = payload.dest;

    if (!clientId || !shopDomain) {
      return htmlResponse(
        'Invalid Token',
        '<h1 class="error">Error – Invalid id_token</h1><p>JWT payload is missing <code>aud</code> or <code>dest</code> claim.</p>',
        400,
      );
    }

    let result;
    try {
      result = await exchangeToken(shopDomain, clientId, secret, idToken);
    } catch (err) {
      return htmlResponse(
        'Exchange Failed',
        `<h1 class="error">Error – Token Exchange Failed</h1><p>${escapeHtml(err.message)}</p>`,
        502,
      );
    }

    const prettyJson = escapeHtml(JSON.stringify(result.data, null, 2));
    const isSuccess = result.status >= 200 && result.status < 300;

    const body = isSuccess
      ? `<h1>Admin API Token</h1>
<p>Shop: <code>${escapeHtml(shopDomain)}</code></p>
<p>App (client_id): <code>${escapeHtml(clientId)}</code></p>
<pre>${prettyJson}</pre>`
      : `<h1 class="error">Error – Shopify Returned ${result.status}</h1>
<pre>${prettyJson}</pre>`;

    return htmlResponse(
      isSuccess ? 'Admin API Token' : `Error ${result.status}`,
      body,
      result.status,
    );
  },
};
