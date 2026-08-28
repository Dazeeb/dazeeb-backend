# DAZEEB backend — Didit KYC integration

Minimal Netlify Functions scaffold for DAZEEB's identity verification,
using Didit's "Free KYC" workflow.

## Files

- `netlify/functions/create-verification-session.js`
  Starts a Didit session for a given user, returns a redirect URL.
- `netlify/functions/didit-webhook.js`
  Receives Didit's status callback. **Signature verification not yet
  implemented — do not deploy publicly until this is done.**
- `.env.example` — required environment variables (copy to `.env` locally,
  set for real in Netlify's dashboard for production).

## Confirmed so far

- Didit workflow in use: **Free KYC**
  (`71fecf71-1781-4a68-9a2e-a22f398f5eca`)
- A test verification (Elijah Elvis Kazibwe, Identity Card, UGA) has
  already been approved via the Didit console directly — confirms the
  workflow itself works.

## Not yet confirmed — do not guess these

- Exact Didit API base URL and session-creation endpoint path/response
  shape (used a plausible `/v2/session/` shape — verify against Didit's
  own API docs before relying on it).
- Didit's webhook signature scheme (header name, algorithm).
- Where DAZEEB persists verification status (DB choice, table/collection
  shape). Both functions have TODOs marking exactly where this plugs in.

## Setup

1. `npm install netlify-cli -g` (if not already installed)
2. Copy `.env.example` to `.env` and fill in real values
3. `netlify dev` to run functions locally
4. Push to GitHub, connect the repo in Netlify, set the same env vars
   in Netlify's dashboard for production
