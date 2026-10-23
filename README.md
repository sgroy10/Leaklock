<div align="center">

# 🔒 LeakLock

### Gitleaks for your live site.

**Find the secret API keys your website gives away to every visitor, including keys no scanner has a pattern for. Get a fix you can paste into Lovable, Bolt or Cursor.**

[![License: MIT](https://img.shields.io/badge/license-MIT-635bff.svg)](LICENSE)
![Free](https://img.shields.io/badge/price-100%25%20free-10b981.svg)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-d946ef.svg)
![Node](https://img.shields.io/badge/node-%3E%3D18-f97316.svg)
[![GitHub stars](https://img.shields.io/github/stars/sgroy10/leaklock?style=social)](https://github.com/sgroy10/leaklock/stargazers)

[**Try it in your browser →**](https://leaklock-production-2a1e.up.railway.app) · [Quick start](#quick-start) · [GitHub Action](#github-action) · [How it works](#how-it-works) · [FAQ](#faq)

</div>

---

```bash
npx github:sgroy10/leaklock scan yourapp.com
```

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

> **LeakLock is free and open source, forever.** No account, no sign-up, no paid tier for scanning. If it helps you, please ⭐ **star the repo** so more builders find it.

## Contents

- [Why this exists](#why-this-exists)
- [What we found scanning real apps](#what-we-found-scanning-real-apps)
- [Quick start](#quick-start)
- [GitHub Action](#github-action)
- [How it works](#how-it-works)
- [What it detects](#what-it-detects)
- [Fixing a leak](#fixing-a-leak)
- [LeakLock vs Gitleaks vs TruffleHog](#leaklock-vs-gitleaks-vs-trufflehog)
- [Use as a library](#use-as-a-library)
- [Self-host the web checker](#self-host-the-web-checker)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Roadmap](#roadmap)

## Why this exists

AI app builders (Lovable, Bolt, v0, Cursor, Replit) make it easy to call an API straight from the frontend. When you do, your build tool bundles the key into JavaScript that **every visitor downloads**. Anyone can open DevTools → Sources, search for `key`, and copy it.

Existing secret scanners look at your **git repo**. But a key can be clean in git and still ship to the browser through a `VITE_` or `NEXT_PUBLIC_` environment variable set in your host's dashboard. LeakLock looks at **what you actually ship**: the HTML, every JS bundle, lazy-loaded chunks and public source maps.

And many APIs (AI image, voice and video services especially) issue plain random strings with no `sk-` prefix. Pattern scanners can't recognise those. LeakLock catches them by **how your code uses them**.

## What we found scanning real apps

In October 2026 we ran LeakLock over **978 live apps** (Lovable, Bolt, Vercel, Netlify and Cloudflare Pages deployments linked from public GitHub projects), reading only the **9,698 files** a normal browser downloads.

| Finding | Apps |
|---|---|
| Shipped at least one secret key to the browser | **37 (1 in 26)** |
| Leaked a critical key (GitHub tokens, admin JWTs) | 6 |
| Exposed a Telegram bot token | 17 |
| Exposed an AI API key (Groq, Gemini, OpenAI, OpenRouter) | 9 |
| Leaked a key **only** usage detection could find | 2 |
| Served public source maps | 8.8% |

Public-by-design keys (Supabase anon, Firebase web, Stripe `pk_`) are not counted. Results are aggregate only: no app is named and every key was masked during the scan. The script is in [`scripts/study.mjs`](scripts/study.mjs) if you want to reproduce it on your own list.

While running the study we found and fixed five false-alarm patterns (form placeholders, Shopify Storefront tokens, Supabase signed URLs, share links and ad tags). Each now has a regression test.

## Quick start

**In your browser (nothing to install):** paste a URL at **https://leaklock-production-2a1e.up.railway.app**

**On your machine** (Node 18+):

```bash
npx github:sgroy10/leaklock scan yourapp.com          # a live site, any host
npx github:sgroy10/leaklock scan dist/                # your build folder
npx github:sgroy10/leaklock scan dist/ --fix          # with step-by-step fixes and an AI-builder prompt
npx github:sgroy10/leaklock scan dist/ --json         # machine-readable output
npx github:sgroy10/leaklock scan dist/ --fail-on=secret   # exit 1 if a secret is found (for CI)
```

**From source:**

```bash
git clone https://github.com/sgroy10/leaklock && cd leaklock
node bin/leaklock.js scan examples/leaky-app/dist --fix   # demo app with fake keys planted on purpose
npm test                                                   # run the test suite
```

| Option | What it does |
|---|---|
| `--fix` | Plain fix steps for each finding, plus a prompt to paste into Lovable, Bolt, Cursor or v0. The prompt never contains your key. |
| `--json` | Full report as JSON (keys masked). |
| `--fail-on=<level>` | Exit code 1 when anything at or above `critical`, `secret` or `review` is found. Default: `secret`. |

Keys are **always masked** (`sk-p…9xQz`). LeakLock never sends your keys anywhere.

## GitHub Action

Fail the pull request before a secret goes live.

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
          target: dist          # a build folder, or a preview URL like https://pr-42.myapp.dev
          fail-on: secret       # critical | secret | review | none
```

The run summary lists every finding (masked). Outputs `critical` and `secret` counts for later steps.

## How it works

```
 your URL or dist/ ──► fetch HTML ──► find every <script>, module preload,
                                      lazy chunk and source map (same site only,
                                      third-party trackers skipped)
                                 │
                                 ▼
          ┌──────────── 1. Known formats ─────────────┐
          │ 30+ provider rules (OpenAI, Stripe,       │
          │ Supabase JWT role decoding, AWS, GitHub…) │
          └───────────────────────────────────────────┘
          ┌──────────── 2. Usage detection ───────────┐
          │ values sent as Authorization: Bearer,     │
          │ x-api-key style headers, or ?key= params; │
          │ minified variables traced to the literal; │
          │ API named from the request host           │
          └───────────────────────────────────────────┘
          ┌──────────── 3. Context ───────────────────┐
          │ public-by-design keys marked SAFE         │
          │ (Stripe pk_, Supabase anon, Firebase web) │
          └───────────────────────────────────────────┘
                                 │
                                 ▼
             masked report  +  fix steps  +  AI-builder prompt
```

Each finding gets a verdict:

| Verdict | Meaning |
|---|---|
| **Critical** | Full control of your backend or money. Rotate now. |
| **Secret** | Anyone can use this API as you and run up your bill. |
| **Review** | Might be fine (e.g. a restricted Google Maps key). Check it. |
| **Safe** | Public by design. Shown so you know it was checked. |

## What it detects

| Verdict | Keys |
|---|---|
| **Critical** | Supabase `service_role` / `sb_secret_`, Stripe `sk_live_` / `rk_live_`, GitHub tokens, AWS access keys, private keys |
| **Secret** | OpenAI, Anthropic, Google Gemini, OpenRouter, Groq, xAI, DeepSeek, Perplexity, Replicate, Hugging Face, ElevenLabs, Resend, SendGrid, Slack, Discord & Slack webhooks, Telegram bots, Mapbox `sk.`, Pinecone, Firecrawl, Google OAuth secrets |
| **Review** | Google API keys without clear context, Stripe test secrets, credential-named variables holding random strings |
| **Safe** | Stripe `pk_`, Supabase `anon` / `sb_publishable_`, Firebase web config |

**Plus any other API**, found by usage: a string sent as `Authorization: Bearer …`, in an `x-api-key` style header, or as `?key=` in a URL, even after a minifier renamed the variable.

Missing a provider? Rules live in [`src/rules.js`](src/rules.js), one small object each. See [Contributing](#contributing).

## Fixing a leak

A key that reaches the browser **cannot be hidden**. Obfuscating, splitting or encrypting it in the frontend fails: it shows up in the Network tab the moment it's sent. The only fix is that the browser never gets it.

1. **Move the call to a server.** A small function (Supabase Edge Function, Vercel or Netlify function, Cloudflare Worker) makes the request instead of the browser.
2. **Keep the key there** as a server secret, never in a `VITE_` or `NEXT_PUBLIC_` variable.
3. **Scan again** to confirm it's gone.
4. **Consider rotating the key.** If it was public, someone may already have a copy.

`--fix` writes this out per finding, with a prompt like:

> My app exposes a kie.ai API key in the browser bundle (found in /assets/Studio-e5f6.js, sent to api.kie.ai). Anyone can copy it. Fix this without changing how the app behaves: 1. Create a server-side function (use a Supabase Edge Function if this project uses Supabase, otherwise a serverless function on our host) that makes the same kie.ai request, reading the key from a secret named KIE_AI_API_KEY. 2. Replace the browser's direct call with a call to that function… 5. Do not change any UI, routes or other logic. List every file you changed.

## LeakLock vs Gitleaks vs TruffleHog

| | LeakLock | Gitleaks | TruffleHog |
|---|---|---|---|
| Scans | your live site or build output | git history and files | git, files, S3, Slack and more |
| Keys with a known format | ✅ 30+ web and AI providers | ✅ hundreds | ✅ 800+ |
| Keys with **no** known format | ✅ found by how they're used | entropy rules only | ❌ |
| Public-by-design keys | ✅ marked safe, with the reason | often flagged | often flagged |
| Fix for each finding | ✅ steps + AI-builder prompt | ❌ | ❌ |
| Checks if a key is still live | planned | ❌ | ✅ |
| License | MIT | MIT | AGPL-3.0 |

They're excellent tools. **Use both:** Gitleaks keeps keys out of git, LeakLock catches the ones that land in your bundle anyway.

## Use as a library

```js
import { scanUrl, scanDir, scanText } from 'leaklock';

const report = await scanUrl('myapp.lovable.app');
console.log(report.summary);   // { critical: 0, secret: 1, review: 0, safe: 1 }

for (const f of report.findings) {
  console.log(f.severity, f.provider, f.masked, f.files);
}
```

## Self-host the web checker

```bash
npm start      # http://localhost:8080
```

The checker only reads public files a browser would load, refuses private and internal addresses, rate-limits each IP, stores nothing, and returns masked keys only, so it can't be used to harvest keys. Deploys as-is to Railway, Render or Fly.

## FAQ

**It found my Supabase anon key. Is that bad?**
No. The anon key is meant to be public; Row Level Security protects your data. The `service_role` key is different: it bypasses all security, and LeakLock marks it critical.

**"No keys found." Am I safe?**
It's good news, not a guarantee. Keys hidden in unusual ways can be missed, and LeakLock doesn't test your database rules or server code.

**Does it send my keys anywhere?**
No. The CLI runs locally. The web checker masks keys before they leave the server and keeps nothing.

**Can I scan someone else's site?**
Only scan sites you own or have permission to test. If you find a leak on someone else's site, tell them privately.

**Is it really free?**
Yes. MIT licensed, no account, no usage limits on the CLI or Action.

## Contributing

Contributions are very welcome, especially new provider rules.

```bash
git clone https://github.com/sgroy10/leaklock && cd leaklock
npm test
```

Adding a provider is one object in [`src/rules.js`](src/rules.js) and one test in [`test/detect.test.js`](test/detect.test.js). See [CONTRIBUTING.md](CONTRIBUTING.md). Found a false positive or a missed key? [Open an issue](https://github.com/sgroy10/leaklock/issues) with a **fake** example (never paste a real key).

## Roadmap

- [x] Detector core + tests
- [x] CLI + web checker
- [x] Unknown-format keys found by usage
- [x] Fix steps + AI-builder prompts
- [x] GitHub Action
- [ ] Vite plugin: warn or fail the build when a secret is about to ship
- [ ] Verify mode: check whether a found key is still live (opt-in, local only)
- [ ] Next.js and Astro build plugins

## License

MIT © [Sandeep Roy](https://github.com/sgroy10). Free for any use.

<div align="center">

**If LeakLock saved you from a leaked key, a ⭐ helps other builders find it.**

</div>
