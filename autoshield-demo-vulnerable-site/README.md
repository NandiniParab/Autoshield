# AutoShield Vulnerable Demo Site

This project is intentionally vulnerable for AutoShield testing and demos only.

Do not deploy it publicly except in a controlled demo environment. It contains deliberate SQL injection, command injection, XSS, weak crypto, hardcoded secrets, vulnerable dependencies, missing security headers, insecure cookies, and media compliance risks.

## Install

```powershell
npm install
```

## Start

```powershell
npm start
```

Open:

```text
http://localhost:4000
```

## Test URLs

```text
http://localhost:4000
http://localhost:4000/search?q=<script>alert(1)</script>
http://localhost:4000/user?email=' OR '1'='1
http://localhost:4000/ping?host=google.com
http://localhost:4000/?code=alert(document.domain)
```

## Expected AutoShield VS Code Findings

- SQL Injection in `db.js`
- Multi-file context from `server.js` to `db.js`
- Data-flow path: `req.query.email -> getUserByEmail(email) -> db.get(query)`
- Command Injection in `/ping`
- Reflected XSS in `/search`
- DOM XSS in `public/app.js`
- Hardcoded secrets in `auth.js` and frontend JavaScript
- Weak MD5/SHA1 crypto in `auth.js`
- Wildcard CORS in `server.js`
- Vulnerable dependencies from `npm audit`
- LangGraph agent trace, RAG validation, confidence, executive summary

## VS Code Demo

1. Start the AutoShield backend.
2. Open this folder in the Extension Development Host.
3. Run `AutoShield: Full Scan (Static + RAG + LLM)` or click `Scan Project`.
4. Show executive risk summary, findings, agent trace, cross-file context, and data-flow evidence.
5. Click `Media Compliance`.
6. Choose local-only scan to flag `stock_banner.jpg`.
7. Choose reverse image search if you have a public image base URL.
8. Export JSON or HTML.

## Chrome Runtime Demo

1. Start the site with `npm start`.
2. Start the AutoShield backend from a terminal where `SERPAPI_API_KEY` is set.
3. Reload the Chrome extension from `chrome://extensions`.
4. Open `http://localhost:4000`.
5. Click `Runtime`.
6. Expected runtime findings include missing security headers, inline scripts, eval usage, mixed content, scripts without integrity, exposed frontend secrets, and insecure cookie evidence where available.
7. Click `Media`.
8. For localhost image URLs, SerpAPI cannot access images directly. Use ngrok or replace image URLs with public image URLs for live reverse-search matches.
9. Export JSON or HTML.

## ngrok Media Demo

For VS Code media reverse search:

```powershell
cd public
python -m http.server 9000
ngrok http 9000
```

Use the ngrok forwarding URL as `public_base_url` in the VS Code media compliance prompt.

For Chrome live media compliance on localhost, expose the whole site:

```powershell
ngrok http 4000
```

Open the ngrok URL in Chrome and click `Media`.

## Media Assets

The included images are copied from the existing AutoShield `media_test` folder:

- `hero.jpg`
- `logo.jpg`
- `stock_banner.jpg`

`stock_banner.jpg` is intentionally named to trigger local media-source risk. For a stronger reverse-search demo, replace these images with public or stock-style images you are allowed to use for testing.
