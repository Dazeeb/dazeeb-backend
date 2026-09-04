// netlify/functions/get-verification.js
//
// What the RECEIVER's screen calls to load a verification result.
// GET /.netlify/functions/get-verification?token=xxxx
//
// Enforces the whole point of this link model:
// - Expired or revoked tokens return nothing.
// - SINGLE USE: the first successful view consumes the link. Any
//   later attempt to open the same token — even seconds later, even
//   still inside the expiry window — returns "already used."
// - Only minimal-disclosure fields are ever returned — never the raw
//   session_id, never anything beyond what the receiver needs to see.

const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const NO_STORE_HEADERS = { "Cache-Control": "no-store" };

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, headers: NO_STORE_HEADERS, body: "Method not allowed" };
  }

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error("Missing required environment variables for get-verification handler");
    return { statusCode: 500, headers: NO_STORE_HEADERS, body: "Server misconfigured" };
  }

  const token = event.queryStringParameters && event.queryStringParameters.token;
  if (!token) {
    return { statusCode: 400, headers: NO_STORE_HEADERS, body: "Missing token" };
  }

  const { data: link, error: linkError } = await supabase
    .from("share_links")
    .select("session_id, expires_at, revoked, used_at")
    .eq("token", token)
    .maybeSingle();

  if (linkError) {
    console.error("Failed to look up share link", linkError);
    return { statusCode: 500, headers: NO_STORE_HEADERS, body: "Storage error" };
  }

  if (!link || link.revoked) {
    return { statusCode: 404, headers: NO_STORE_HEADERS, body: "Link not found" };
  }

  if (link.used_at) {
    return { statusCode: 410, headers: NO_STORE_HEADERS, body: "This link has already been used" };
  }

  if (new Date(link.expires_at).getTime() <= Date.now()) {
    return { statusCode: 410, headers: NO_STORE_HEADERS, body: "This link has expired" };
  }

  const { data: verification, error: verificationError } = await supabase
    .from("verifications")
    .select(
      "status, first_name, last_name_initial, age_over_18, id_verification_status, liveness_status, face_match_status"
    )
    .eq("session_id", link.session_id)
    .maybeSingle();

  if (verificationError) {
    console.error("Failed to look up verification", verificationError);
    return { statusCode: 500, headers: NO_STORE_HEADERS, body: "Storage error" };
  }

  if (!verification) {
    return { statusCode: 404, headers: NO_STORE_HEADERS, body: "Verification not found" };
  }

  // Consume the link now, atomically, only if it's still unused.
  // The .is("used_at", null) guard means: if two requests race to view
  // this token at the same instant, only one of them can win this
  // update — the other gets 0 rows updated and is treated as already used.
  const { data: consumed, error: consumeError } = await supabase
    .from("share_links")
    .update({ used_at: new Date().toISOString() })
    .eq("token", token)
    .is("used_at", null)
    .select("token");

  if (consumeError) {
    console.error("Failed to mark share link as used", consumeError);
    return { statusCode: 500, headers: NO_STORE_HEADERS, body: "Storage error" };
  }

  if (!consumed || consumed.length === 0) {
    // Someone else consumed it in the instant between our check above
    // and this update — treat as already used.
    return { statusCode: 410, headers: NO_STORE_HEADERS, body: "This link has already been used" };
  }

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json", ...NO_STORE_HEADERS },
    body: JSON.stringify({
      ...verification,
      expires_at: link.expires_at,
    }),
  };
};
