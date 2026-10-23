# 🔒 LeakLock

**Gitleaks checks your repo. LeakLock checks what you ship.**

Find the secret API keys your website hands to every visitor, including keys for APIs no scanner has a pattern for. Then get a fix you can paste straight into Lovable, Bolt or Cursor.

```bash
npx leaklock scan yourapp.com          # any live site, any host
npx leaklock scan dist/ --fix          # your build folder, with fixes
```

Or paste a URL into the free web checker: **https://leaklock-production-2a1e.up.railway.app**

```
LeakLock scanned https://myapp.lovable.app/ (6 files)

CRITICAL Supabase service_role key (project abcdefghijklmnop)  eyJh…Xk2Q
         in /assets/index-a1b2.js
SECRET   kie.ai API key  d41f…a07c
         in /assets/Studio-e5f6.js
         A secret key sent as a Bearer token to api.kie.ai. Anyone can copy it
         from your site and call that API as you.
SAFE     Supabase anon key (project abcdefghijklmnop)  eyJh…c3Rw
         Public by design. Your data is only as safe as your Row Level Security policies.

1 critical · 1 secret · 0 to review · 1 safe (public by design)
```

## Not every key starts with `sk-`

Pattern scanners (Gitleaks, TruffleHog, and most "is my app leaking" checkers) only find key formats they've been taught. Plenty of AI, image and voice APIs hand out plain random strings, like 32 hex characters with no prefix. Those sail straight through.

LeakLock also catches a key by **how your code uses it**: sent as `Authorization: Bearer …`, in an `x-api-key` style header, or as `?key=` in a URL. It follows minified variables back to the literal they hold, and names the API from where the request goes (`api.kie.ai` → "kie.ai API key").

Try it on the demo app, which has fake keys planted on purpose:

```bash
git clone https://github.com/sgroy10/leaklock && cd leaklock
node bin/leaklock.js scan examples/leaky-app/dist --fix
```

| | Gitleaks / TruffleHog | LeakLock |
|---|---|---|
| Scans | git history, files | what your live site or build actually serves (HTML, bundles, lazy chunks, source maps) |
| Keys with a known format | ✅ hundreds | ✅ 30+ that matter for web apps |
| Keys with **no** known format | ❌ (or noisy entropy guesses) | ✅ found by usage, traced through minified code |
| Public-by-design keys (`pk_`, Supabase anon, Firebase) | often flagged | marked safe, with the reason |
| Fix for each leak | ❌ | ✅ steps plus a prompt for your AI builder |

Use both: Gitleaks keeps keys out of git, LeakLock catches the ones that slip into your bundle through `VITE_` / `NEXT_PUBLIC_` variables.

## GitHub Action

```yaml
# .github/workflows/leaklock.yml
name: leaklock
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
      - uses: sgroy10/leaklock@v1
        with:
          target: dist          # or a preview URL, e.g. https://pr-42.myapp.dev
          fail-on: secret       # critical | secret | review | none
```

The job fails when a secret is about to ship, and the run summary lists every finding (masked).

## Fixes you can paste

`--fix` (and the web checker) gives each leak plain steps and a prompt for the AI builder that made your app, e.g.:

> My app exposes a kie.ai API key in the browser bundle (found in /assets/Studio-e5f6.js, sent to api.kie.ai). Anyone can copy it. Fix this without changing how the app behaves: 1. Create a server-side function (use a Supabase Edge Function if this project uses Supabase…) that makes the same kie.ai request, reading the key from a secret named KIE_AI_API_KEY. 2. Replace the browser's direct call with a call to that function… 5. Do not change any UI, routes or other logic.

The prompt never contains your key.

## Why LeakLock

- **Works on any site.** Custom domains, ccTLDs (`.co.in`, `.com.au`), CDN-hosted bundles, Vite, Next.js and webpack chunks. Third-party trackers are skipped so their keys aren't blamed on you.
- **Scans what ships, not your repo.** HTML, inline scripts, every JS bundle, lazy-loaded chunks, and public source maps. That's where keys actually leak.
- **No false alarms.** Stripe `pk_`, Supabase `anon` and Firebase web keys are public by design. LeakLock decodes Supabase JWTs to tell `anon` from `service_role`, and reads context to tell a Firebase config from a Gemini call.
- **Never shows a full key.** Output is always masked (`sk-p…9xQz`). The web checker stores nothing.
- **Zero dependencies.** One small, auditable Node package.
- **CI-ready.** `--fail-on=secret` exits 1 when a secret is in your build. `--json` for scripts. GitHub Action included.

## What it detects

| Verdict | Keys |
|---|---|
| **Critical** | Supabase `service_role` / `sb_secret_`, Stripe `sk_live_` / `rk_live_`, GitHub tokens, AWS access keys, private keys |
| **Secret** | OpenAI, Anthropic, Google Gemini, OpenRouter, Groq, xAI, DeepSeek, Perplexity, Replicate, Hugging Face, ElevenLabs, Resend, SendGrid, Slack, Discord & Slack webhooks, Telegram bots, Mapbox `sk.`, Pinecone, Firecrawl, Google OAuth secrets |
| **Check** | Google API keys without clear context (Maps keys are fine *if* restricted), Stripe test secrets |
| **Safe** | Stripe `pk_`, Supabase `anon` / `sb_publishable_`, Firebase web config |

**Any other API** is caught by how the key is used, not its shape: a string sent as `Authorization: Bearer …`, in an `x-api-key` style header, or as `?key=` in a URL, even when a minifier renamed the variable. LeakLock follows the variable back to its value and names the API from where the request goes (`api.kie.ai` → "kie.ai API key"). Credential-named variables (`apiKey`, `SECRET_TOKEN`) holding random strings are flagged for review.

Missing a provider? Open an issue or a PR: rules live in [`src/rules.js`](src/rules.js), one object each.

## Two hard truths

1. **A key that reaches the browser cannot be hidden.** Obfuscation, splitting and in-browser encryption all fail: the key is visible in the Network tab the moment it's sent.
2. **A key that was public may already be copied.** Moving it to a server stops new copies; rotating it cuts off anyone who already took it.

## Use as a library

```js
import { scanUrl, scanDir, scanText } from 'leaklock';

const report = await scanUrl('myapp.lovable.app');
console.log(report.summary); // { critical: 1, secret: 1, review: 0, safe: 1 }
```

## Run the web checker yourself

```bash
npm start            # http://localhost:8080
```

The checker only reads public files a browser would load, refuses private/internal addresses, rate-limits each IP, and returns masked keys only, so it can't be used to harvest keys.

## Roadmap

- [x] Detector core + tests
- [x] CLI + web checker
- [x] Unknown-format keys found by usage
- [x] Fix steps + AI-builder prompts
- [x] GitHub Action
- [ ] Vite plugin: warn (or fail) the build when a secret is about to ship
- [ ] Verify mode: check whether a found key is still live (opt-in, local only)
- [ ] **Shield**: swap the real key in your build for a useless `ll_pub_` token and route calls through a tiny proxy in *your own* Cloudflare or Supabase account (origin check, endpoint allow-list, rate limit, daily cap). No code changes.

## License

MIT © [Sandeep Roy](https://github.com/sgroy10)

Only scan sites you own or have permission to test.
