// netlify/functions/didit-webhook.js
//
// Receives status updates from Didit when a verification session
// completes, fails, or changes state.
//
// Signature verification confirmed against docs.didit.me/reference/webhooks
// and docs.didit.me's HMAC guide:
//   - Header 'x-signature'  : hex HMAC-SHA256 of the RAW request body,
//     keyed with your webhook's secret (Settings > Webhooks > signing secret).
//   - Header 'x-timestamp'  : unix seconds; reject if more than 5 minutes old
//     (replay-attack protection).
//   - Didit also sends 'x-signature-v2' (canonical-JSON based) for cases where
//     a proxy/framework re-encodes the body and breaks the plain x-signature
//     check. This function verifies x-signature only, which is enough as
//     long as Netlify passes the body through unmodified — confirm this
//     holds once you test a real webhook delivery; switch to v2 if signatures
//     ever fail to match despite a correct secret.
//
// Required environment variables:
//   DIDIT_WEBHOOK_SECRET - the signing secret shown on the Webhooks tab
//                           when you add a destination (only shown once)

const crypto = require('crypto');

function verifySignature(rawBody, signatureHeader, timestampHeader, secret) {
  if (!signatureHeader || !timestampHeader || !rawBody || !secret) return false;

  const timestamp = parseInt(timestampHeader, 10);
  if (!Number.isFinite(timestamp)) return false;
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestamp) > 300) return false; // reject if older than 5 min

  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

  const sigBuf = Buffer.from(signatureHeader, 'utf8');
  const expBuf = Buffer.from(expected, 'utf8');
  if (sigBuf.length !== expBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, expBuf);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const secret = process.env.DIDIT_WEBHOOK_SECRET;
  if (!secret) {
    console.error('DIDIT_WEBHOOK_SECRET is not set');
    return { statusCode: 500, body: 'Server misconfiguration' };
  }

  const rawBody = event.body || '';
  const signature = event.headers['x-signature'] || event.headers['X-Signature'];
  const timestamp = event.headers['x-timestamp'] || event.headers['X-Timestamp'];

  if (!verifySignature(rawBody, signature, timestamp, secret)) {
    console.warn('Didit webhook signature verification failed');
    return { statusCode: 401, body: 'Invalid signature' };
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    return { statusCode: 400, body: 'Invalid JSON body' };
  }

  const { session_id, status, vendor_data } = payload;

  if (!session_id || !status) {
    return { statusCode: 400, body: 'Missing session_id or status' };
  }

  // TODO: look up the DAZEEB user by session_id / vendor_data and update
  // their verification status in storage. Keep this deterministic —
  // status must come only from Didit's payload, never inferred.

  console.log(`Didit webhook received: session=${session_id} status=${status} vendor_data=${vendor_data}`);

  return { statusCode: 200, body: 'OK' };
};
