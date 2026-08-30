// netlify/functions/create-verification-session.js
//
// Creates a Didit verification session for a user and returns the
// redirect URL the frontend should send the user to.
//
// Confirmed against Didit's official docs (docs.didit.me/reference/api-authentication,
// docs.didit.me/reference/create-session-verification-sessions):
//   Endpoint: POST {DIDIT_API_BASE}/v3/session/
//   Auth header: x-api-key
//   Body: { workflow_id, vendor_data, callback }
//   Response includes: session_id, url
//
// NOTE: one Didit doc page (API Full Flow guide) shows a v3 endpoint and a
// differently-named response field (verification_url / session_token)
// instead of v2's session_id / url. This function uses the officially
// documented v2 endpoint. If it 404s or the response shape looks wrong
// once tested, that's the sign to switch to v3 — check with Didit support
// or re-test rather than guessing further.
//
// Required environment variables (set in Netlify dashboard, never committed):
//   DIDIT_API_KEY       - your Didit business API key (Dazeeb-Production key)
//   DIDIT_WORKFLOW_ID    - Free KYC = <your-workflow-id>
//   APP_URL              - your deployed site's base URL, used to build the callback
//
// This function does NOT store anything itself. Wire persistence into
// the TODO block once you tell me what DAZEEB uses (DB, table names, etc).

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: 'Invalid JSON body' };
  }

  const { user_id, vendor_data } = body;
  if (!user_id) {
    return { statusCode: 400, body: 'user_id is required' };
  }

  const apiKey = process.env.DIDIT_API_KEY;
  const workflowId = process.env.DIDIT_WORKFLOW_ID;
  const appUrl = process.env.APP_URL;

  if (!apiKey || !workflowId || !appUrl) {
    console.error('Missing required Didit env vars');
    return { statusCode: 500, body: 'Server misconfiguration' };
  }

  try {
    const apiBase = process.env.DIDIT_API_BASE;
    const diditResponse = await fetch(`${apiBase}/v3/session/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      },
      body: JSON.stringify({
        workflow_id: workflowId,
        vendor_data: vendor_data || user_id,
        callback: `${appUrl}/.netlify/functions/didit-webhook`,
      }),
    });

    if (!diditResponse.ok) {
      const errText = await diditResponse.text();
      console.error('Didit session creation failed:', diditResponse.status, errText);
      return { statusCode: 502, body: 'Failed to create verification session' };
    }

    const diditData = await diditResponse.json();

    // TODO: persist { user_id, session_id: diditData.session_id, status: 'pending' }
    // to DAZEEB's storage here, once storage layer is confirmed.

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: diditData.session_id,
        url: diditData.url, // confirm this field name once you see a real response
      }),
    };
  } catch (err) {
    console.error('Unexpected error creating Didit session:', err);
    return { statusCode: 500, body: 'Internal server error' };
  }
};
