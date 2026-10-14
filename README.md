# CyberLeak

A self-hosted breach checker in the spirit of Have I Been Pwned. It lets people:

- **Check an email address** against known data breaches
- **Check a password** against hundreds of millions of leaked passwords, without ever sending the password
- **Browse the breach catalogue**: every known breach, what was exposed, and how many accounts

It uses the official Have I Been Pwned (HIBP) APIs as its data source, so results are real.

## Run it

Requires Node.js 18 or newer. No packages to install.

```bash
cp .env.example .env      # optional: add your HIBP API key
node server.js
```

Open http://localhost:3000.

## What needs an API key

| Feature | Key needed? | Source |
|---|---|---|
| Password check | No | `api.pwnedpasswords.com/range/{prefix}` (free) |
| Breach catalogue | No | `haveibeenpwned.com/api/v3/breaches` (free) |
| Email lookup | **Yes** | `haveibeenpwned.com/api/v3/breachedaccount/{email}` (paid subscription) |

Get a key at https://haveibeenpwned.com/API/Key and put it in `.env` as `HIBP_API_KEY=...`.

**Without a key, email lookups still work for free** through [XposedOrNot](https://xposedornot.com)'s public API (`/v1/breach-analytics`). The browser calls it directly, so each visitor gets their own free allowance (about 25 checks an hour and 100 a day per IP). If the browser call is blocked, the page falls back to `/api/xon` on the server, which shares one allowance across all visitors. XposedOrNot's free API is meant for personal and low-volume use; for heavier use, add an HIBP key or a paid XposedOrNot plan. Once `HIBP_API_KEY` is set, email lookups switch to HIBP automatically.

## How the password check stays private (k-anonymity)

1. The browser hashes the password with SHA-1 (e.g. `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`).
2. Only the first 5 characters (`5BAA6`) go to the server, which forwards them to Pwned Passwords.
3. The API returns every leaked hash suffix that starts with that prefix (hundreds of them), padded so the response size reveals nothing.
4. The browser looks for its remaining 35 characters in that list. The match never leaves the device.

## Security choices

- The HIBP API key lives only on the server; the browser never sees it.
- Email lookups are rate-limited per IP (`EMAIL_LIMIT_PER_MIN`, default 10) to stop the app being used to bulk-scan addresses.
- The server never logs email addresses or query strings.
- Breach descriptions from the API contain HTML; the page converts them to plain text before display.
- Strict security headers (CSP, no framing, no referrer).

## Deploying

**Vercel (set up in this repo):** `public/` is served as static files and `api/` runs as serverless functions, sharing logic in `lib/hibp.js`. Import the repo in Vercel; no build step is needed. To enable email lookups, add `HIBP_API_KEY` under Project → Settings → Environment Variables and redeploy. On serverless, the per-IP rate limit is best-effort (each warm instance counts separately); add Vercel's firewall rate limiting for a hard cap.

**Any other Node host** (Render, Railway, Fly.io, a VPS): run `node server.js` with `HIBP_API_KEY` and `PORT` set. Serve it over HTTPS: browsers only allow in-page hashing (`crypto.subtle`) on HTTPS or localhost.

If you deploy behind a reverse proxy, the rate limiter trusts the first `X-Forwarded-For` address. Only expose the app through a proxy that sets that header.

## Ideas for next steps

- Breach notifications: let users verify their email and get alerted when it appears in a new breach (HIBP offers domain and subscription APIs for this).
- Domain search for organisations (requires verifying domain ownership with HIBP).
- Your own breach database: HIBP itself works by loading breach dumps into an index. Building one means handling stolen personal data, which carries serious legal and ethical obligations (data protection law, secure storage, disclosure process). Using the HIBP API avoids that.

## Attribution

Breach and password data: [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt, licensed CC BY 4.0. Attribution is required by the license and is shown in the app footer.
