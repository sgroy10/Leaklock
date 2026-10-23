# 🔒 LeakLock

**Is your app leaking API keys? Find out in 10 seconds.**

Any website can leak, on your own domain or any host. Vibe-coded apps (Lovable, Bolt, v0, Cursor, Next.js, plain Vite) especially often ship secret keys inside the JavaScript every visitor downloads. Anyone can press **Inspect → Sources**, search for `sk-`, and run up your OpenAI bill, empty your Gemini credits, or read your whole Supabase database.

LeakLock scans what your site actually sends to the browser and tells you, in plain words, which keys are exposed and what to do.

```bash
npx leaklock scan yourapp.com          # any live site, any host
npx leaklock scan dist/                # your build folder, before you publish
```

```
LeakLock scanned https://myapp.lovable.app/ (6 files)

CRITICAL Supabase service_role key (project abcdefghijklmnop)  eyJh…Xk2Q
         in /assets/index-a1b2.js
         The service_role key bypasses Row Level Security. Anyone with it can read,
         change or delete your entire database. Rotate the JWT secret now.
SECRET   OpenAI  sk-p…9xQz
         in /assets/Chat-e5f6.js, /assets/index-a1b2.js.map
         Rotate: https://platform.openai.com/api-keys
SAFE     Supabase anon key (project abcdefghijklmnop)  eyJh…c3Rw
         Public by design. Your data is only as safe as your Row Level Security policies.

Note: 1 source map(s) are public, so your original source code is readable too.

1 critical · 1 secret · 0 to review · 1 safe (public by design)
```

## Why LeakLock

- **Works on any site.** Custom domains, ccTLDs (`.co.in`, `.com.au`), CDN-hosted bundles, Vite, Next.js and webpack chunks. Third-party trackers are skipped so their keys aren't blamed on you.
- **Scans what ships, not your repo.** HTML, inline scripts, every JS bundle, lazy-loaded chunks, and public source maps. That's where keys actually leak.
- **No false alarms.** Stripe `pk_`, Supabase `anon` and Firebase web keys are public by design. LeakLock decodes Supabase JWTs to tell `anon` from `service_role`, and reads context to tell a Firebase config from a Gemini call.
- **Never shows a full key.** Output is always masked (`sk-p…9xQz`). The web checker stores nothing.
- **Zero dependencies.** One small, auditable Node package.
- **CI-ready.** `--fail-on=secret` exits 1 when a secret is in your build. `--json` for scripts.

## What it detects

| Verdict | Keys |
|---|---|
| **Critical** | Supabase `service_role` / `sb_secret_`, Stripe `sk_live_` / `rk_live_`, GitHub tokens, AWS access keys, private keys |
| **Secret** | OpenAI, Anthropic, Google Gemini, OpenRouter, Groq, xAI, DeepSeek, Perplexity, Replicate, Hugging Face, ElevenLabs, Resend, SendGrid, Slack, Discord & Slack webhooks, Telegram bots, Mapbox `sk.`, Pinecone, Firecrawl, Google OAuth secrets |
| **Check** | Google API keys without clear context (Maps keys are fine *if* restricted), Stripe test secrets |
| **Safe** | Stripe `pk_`, Supabase `anon` / `sb_publishable_`, Firebase web config |

Missing a provider? Open an issue or a PR: rules live in [`src/rules.js`](src/rules.js), one object each.

## Two hard truths

1. **A key that reaches the browser cannot be hidden.** Obfuscation, splitting and in-browser encryption all fail: the key is visible in the Network tab the moment it's sent.
2. **A key that was public is burned.** Rotate it once, then keep the new one off the browser.

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
- [ ] Vite plugin: warn (or fail) the build when a secret is about to ship
- [ ] **Shield**: swap the real key in your build for a useless `ll_pub_` token and route calls through a tiny proxy in *your own* Cloudflare or Supabase account (origin check, endpoint allow-list, rate limit, daily cap). No code changes.
- [ ] Lovable MCP tools and Bolt one-line install

## License

MIT © [Sandeep Roy](https://github.com/sgroy10), maker of [SpecLock](https://github.com/sgroy10/speclock).
