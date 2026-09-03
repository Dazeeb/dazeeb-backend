// netlify/functions/didit-webhook.js
//
// Receives Didit's "status.updated" webhook for KYC sessions, verifies its
// authenticity, and stores ONLY the minimal fields DAZEEB's receiver screen
// needs. Didit remains the custodian of the full raw decision data.
//
// Required environment variables (already set in Netlify):
//   DIDIT_WEBHOOK_SECRET        - the destination's secret_shared_key from the Didit Business Console
//   SUPABASE_URL                - your Supabase project URL
//   SUPABASE_SERVICE_ROLE_KEY   - service_role / sb_secret_ key (server-side ONLY, bypasses RLS)

const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const MAX_TIMESTAMP_SKEW_SECONDS = 300; // reject anything older than 5 minutes (replay protection)

// --- Signature verification -------------------------------------------------

function shortenFloats(data) {
  if (Array.isArray(data)) return data.map(shortenFloats);
  if (data !== null && typeof data === "object") {
    return Object.fromEntries(Object.entries(data).map(([k, v]) => [k, shortenFloats(v)]));
  }
  if (typeof data === "number" && !Number.isInteger(data) && data % 1 === 0) {
    return Math.trunc(data);
  }
  return data;
}

function sortKeys(obj) {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj)
      .sort()
      .reduce((acc, k) => {
        acc[k] = sortKeys(obj[k]);
        return acc;
      }, {});
  }
  return obj;
}

function timestampIsFresh(timestampHeader) {
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestampHeader, 10);
  if (!Number.isFinite(ts)) return false;
  return Math.abs(now - ts) <= MAX_TIMESTAMP_SKEW_SECONDS;
}

function safeEqual(expectedHex, providedHex) {
  const a = Buffer.from(expectedHex, "utf8");
  const b = Buffer.from(providedHex, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function verifySignatureV2(bodyJson, sigHeader, secret) {
  const canonical = JSON.stringify(sortKeys(shortenFloats(bodyJson)));
  const expected = crypto.createHmac("sha256", secret).update(canonical, "utf8").digest("hex");
  return safeEqual(expected, sigHeader);
}

function verifySignatureSimple(rawBody, sigHeader, secret) {
  const expected = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest("hex");
  return safeEqual(expected, sigHeader);
}

// --- Minimal-disclosure extraction ------------------------------------------

function ageOver18FromDob(dobString) {
  if (!dobString) return null;
  const dob = new Date(dobString);
  if (Number.isNaN(dob.getTime())) return null;
  const now = new Date();
  let age = now.getFullYear() - dob.getFullYear();
  const hasHadBirthdayThisYear =
    now.getMonth() > dob.getMonth() || (now.getMonth() === dob.getMonth() && now.getDate() >= dob.getDate());
  if (!hasHadBirthdayThisYear) age -= 1;
  return age >= 18;
}

function extractMinimalFields(decision) {
  if (!decision) return {};

  const idv = decision.id_verifications?.[0];
  const liveness = decision.liveness_checks?.[0];
  const faceMatch = decision.face_matches?.[0];

  const ageOver18 = idv?.date_of_birth ? ageOver18FromDob(idv.date_of_birth) : null;

  return {
    first_name: idv?.first_name ?? null,
    last_name_initial: idv?.last_name ? idv.last_name.trim().charAt(0).toUpperCase() : null,
    age_over_18: ageOver18,
    id_verification_status: idv?.status ?? null,
    liveness_status: liveness?.status ?? null,
    liveness_score: liveness?.score ?? null,
    face_match_status: faceMatch?.status ?? null,
    face_match_score: faceMatch?.score ?? null,
  };
}

// --- Handler -----------------------------------------------------------------

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  const secret = process.env.DIDIT_WEBHOOK_SECRET;
  if (!secret || !process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error("Missing required environment variables for Didit webhook handler");
    return { statusCode: 500, body: "Server misconfigured" };
  }

  const rawBody = event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;

  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return { statusCode: 400, body: "Invalid JSON" };
  }

  const headers = Object.fromEntries(Object.entries(event.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const sigV2 = headers["x-signature-v2"];
  const sigSimple = headers["x-signature"];
  const timestamp = headers["x-timestamp"];

  if (!timestamp || !timestampIsFresh(timestamp)) {
    return { statusCode: 401, body: "Missing or stale timestamp" };
  }

  let verified = false;
  let verifiedViaSimpleOnly = false;

  if (sigV2 && verifySignatureV2(body, sigV2, secret)) {
    verified = true;
  } else if (sigSimple && verifySignatureSimple(rawBody, sigSimple, secret)) {
    verified = true;
    verifiedViaSimpleOnly = true;
  }

  if (!verified) {
    console.warn("Didit webhook signature verification failed", { session_id: body.session_id });
    return { statusCode: 401, body: "Invalid signature" };
  }

  const eventId = body.event_id || `${body.session_id}:${body.timestamp || timestamp}`;

  const { error: dedupeError } = await supabase
    .from("processed_webhook_events")
    .insert({ event_id: eventId });

  if (dedupeError) {
    if (dedupeError.code === "23505") {
      return { statusCode: 200, body: JSON.stringify({ ok: true, deduped: true }) };
    }
    console.error("Failed to record processed event", dedupeError);
    return { statusCode: 500, body: "Storage error" };
  }

  if (body.webhook_type && body.webhook_type !== "status.updated") {
    return { statusCode: 200, body: JSON.stringify({ ok: true, ignored: true }) };
  }

  const minimalFields =
    !verifiedViaSimpleOnly && body.decision ? extractMinimalFields(body.decision) : {};

  const { error: upsertError } = await supabase.from("verifications").upsert(
    {
      session_id: body.session_id,
      vendor_data: body.vendor_data ?? null,
      status: body.status,
      updated_at: new Date().toISOString(),
      ...minimalFields,
    },
    { onConflict: "session_id" }
  );

  if (upsertError) {
    console.error("Failed to upsert verification", upsertError);
    return { statusCode: 500, body: "Storage error" };
  }

  console.log(`Didit webhook processed: session=${body.session_id} status=${body.status}`);

  return { statusCode: 200, body: JSON.stringify({ ok: true }) };
};
