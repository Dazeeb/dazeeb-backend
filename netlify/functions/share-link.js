// netlify/functions/share-link.js
//
// Mints a single-use share link for an already-completed verification.
// Each call creates ONE new token — the link it produces can be opened
// successfully exactly once (get-verification.js enforces that) and
// expires after a short window regardless.
//
// POST body: { session_id: string, expiry_minutes?: number (default 3) }
// Response:  { token, url, expires_at }

const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const RATE_LIMIT_WINDOW_MINUTES = 10;
const RATE_LIMIT_MAX_MINTS = 5;
const DEFAULT_EXPIRY_MINUTES = 3;

function generateToken() {
  return crypto.randomBytes(16).toString("base64url");
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error("Missing required environment variables for share-link handler");
    return { statusCode: 500, body: "Server misconfigured" };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    return { statusCode: 400, body: "Invalid JSON body" };
  }

  const sessionId = body.session_id;
  if (!sessionId) {
    return { statusCode: 400, body: "Missing session_id" };
  }

  const expiryMinutes = Number.isFinite(body.expiry_minutes) && body.expiry_minutes > 0
    ? body.expiry_minutes
    : DEFAULT_EXPIRY_MINUTES;

  // Confirm the verification actually exists before minting anything.
  const { data: verification, error: verificationError } = await supabase
    .from("verifications")
    .select("session_id")
    .eq("session_id", sessionId)
    .maybeSingle();

  if (verificationError) {
    console.error("Failed to look up verification", verificationError);
    return { statusCode: 500, body: "Storage error" };
  }

  if (!verification) {
    return { statusCode: 404, body: "Verification not found" };
  }

  // Rate limit: cap how many links can be minted per session_id in a window,
  // to stop someone generating unlimited fresh links to route around the
  // single-use rule.
  const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW_MINUTES * 60 * 1000).toISOString();
  const { count, error: countError } = await supabase
    .from("share_links")
    .select("token", { count: "exact", head: true })
    .eq("session_id", sessionId)
    .gte("created_at", windowStart);

  if (countError) {
    console.error("Failed to check rate limit", countError);
    return { statusCode: 500, body: "Storage error" };
  }

  if ((count || 0) >= RATE_LIMIT_MAX_MINTS) {
    return { statusCode: 429, body: "Too many links generated for this verification recently" };
  }

  const token = generateToken();
  const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString();

  const { error: insertError } = await supabase
    .from("share_links")
    .insert({
      token,
      session_id: sessionId,
      expires_at: expiresAt,
      revoked: false,
    });

  if (insertError) {
    console.error("Failed to create share link", insertError);
    return { statusCode: 500, body: "Storage error" };
  }

  const url = `https://dazeeb-backend.netlify.app/verify/${token}`;

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify({ token, url, expires_at: expiresAt }),
  };
};
