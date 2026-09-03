// netlify/functions/share-link.js
//
// Mints a short-lived share link for an already-completed verification.
// Used both for the initial share AND for "resend" — resend is just this
// same operation again: a new token pointing at the same underlying
// verification, no re-scan, no new Didit session.
//
// POST body: { session_id: string, expiry_minutes?: number (default 10) }
// Response:  { token, url, expires_at }
//
// Known limitation (accepted for now, not solved here): the only
// "credential" required to mint a link is knowing the session_id. There
// is no account/login system yet to verify the caller is actually the
// person who completed that verification. Revisit once DAZEEB has real
// user accounts.

const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const DEFAULT_EXPIRY_MINUTES = 10;
const MIN_EXPIRY_MINUTES = 1;
const MAX_EXPIRY_MINUTES = 24 * 60; // 1 day ceiling, sender can't set something absurd

function generateToken() {
  // 16 random bytes, base64url-encoded -> 22 char URL-safe token
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
  } catch {
    return { statusCode: 400, body: "Invalid JSON" };
  }

  const { session_id } = body;
  if (!session_id) {
    return { statusCode: 400, body: "Missing session_id" };
  }

  let expiryMinutes = Number(body.expiry_minutes) || DEFAULT_EXPIRY_MINUTES;
  expiryMinutes = Math.min(Math.max(expiryMinutes, MIN_EXPIRY_MINUTES), MAX_EXPIRY_MINUTES);

  const { data: verification, error: lookupError } = await supabase
    .from("verifications")
    .select("session_id, status")
    .eq("session_id", session_id)
    .maybeSingle();

  if (lookupError) {
    console.error("Failed to look up verification", lookupError);
    return { statusCode: 500, body: "Storage error" };
  }

  if (!verification) {
    return { statusCode: 404, body: "No verification found for that session_id" };
  }

  // Rate limit: cap link-mints per session_id to blunt abuse of a leaked
  // session_id, since there's no account system yet to gate this properly.
  const RATE_LIMIT_WINDOW_MINUTES = 10;
  const RATE_LIMIT_MAX = 5;
  const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW_MINUTES * 60 * 1000).toISOString();

  const { count: recentCount, error: rateError } = await supabase
    .from("share_links")
    .select("token", { count: "exact", head: true })
    .eq("session_id", session_id)
    .gte("created_at", windowStart);

  if (rateError) {
    console.error("Failed to check rate limit", rateError);
    return { statusCode: 500, body: "Storage error" };
  }

  if (recentCount !== null && recentCount >= RATE_LIMIT_MAX) {
    return { statusCode: 429, body: "Too many link requests — try again shortly" };
  }

  const token = generateToken();
  const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString();

  const { error: insertError } = await supabase.from("share_links").insert({
    token,
    session_id,
    expires_at: expiresAt,
  });

  if (insertError) {
    console.error("Failed to create share link", insertError);
    return { statusCode: 500, body: "Storage error" };
  }

  const baseUrl = process.env.APP_URL || "https://dazeeb.com";
  const url = `${baseUrl.replace(/\/$/, "")}/verify/${token}`;

  return {
    statusCode: 200,
    body: JSON.stringify({ token, url, expires_at: expiresAt }),
  };
};
