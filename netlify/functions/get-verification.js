// netlify/functions/get-verification.js
//
// What the RECEIVER's screen calls to load a verification result.
// GET /.netlify/functions/get-verification?token=xxxx
//
// Enforces the whole point of this link model: expired or revoked tokens
// return nothing, and only minimal-disclosure fields are ever returned —
// never the raw session_id, never anything beyond what the receiver
// actually needs to see.

const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error("Missing required environment variables for get-verification handler");
    return { statusCode: 500, body: "Server misconfigured" };
  }

  const token = event.queryStringParameters && event.queryStringParameters.token;
  if (!token) {
    return { statusCode: 400, body: "Missing token" };
  }

  const { data: link, error: linkError } = await supabase
    .from("share_links")
    .select("session_id, expires_at, revoked")
    .eq("token", token)
    .maybeSingle();

  if (linkError) {
    console.error("Failed to look up share link", linkError);
    return { statusCode: 500, body: "Storage error" };
  }

  if (!link || link.revoked) {
    return { statusCode: 404, body: "Link not found" };
  }

  if (new Date(link.expires_at).getTime() <= Date.now()) {
    return { statusCode: 410, body: "This link has expired" };
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
    return { statusCode: 500, body: "Storage error" };
  }

  if (!verification) {
    return { statusCode: 404, body: "Verification not found" };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      ...verification,
      expires_at: link.expires_at,
    }),
  };
};
