# Contributing to LeakLock

Thanks for helping. LeakLock is free and MIT licensed, and new provider rules are the most useful contribution.

## Setup

```bash
git clone https://github.com/sgroy10/leaklock && cd leaklock
npm test        # Node 18+, no dependencies to install
```

## Add a provider rule

1. Open [`src/rules.js`](src/rules.js) and add one object. More specific rules go first.

```js
{
  id: 'acme',                       // short, unique
  provider: 'Acme',                 // shown to the user
  severity: 'secret',               // critical | secret | review | safe
  re: /\bacme_live_[A-Za-z0-9]{32}\b/g,
  endpoint: 'https://api.acme.com', // optional: used in the fix prompt
  rotate: 'https://acme.com/settings/keys', // optional: where to create a new key
}
```

2. Add a **fake** key to [`test/fixtures.js`](test/fixtures.js) and a case to [`test/detect.test.js`](test/detect.test.js).
3. Run `npm test` and open a pull request.

## Rules of the road

- Never commit or paste a real key, not even a revoked one. Build fake keys that match the shape.
- Prefer precise patterns over broad ones. A false alarm on a public-by-design key is a bug.
- If a key type is public by design, add it as `safe` with a one-line reason.
- Keep it dependency-free.

## Reporting a bug

Open an issue with the command you ran, what you expected, and a **fake** snippet that reproduces it.

## Security

Found a way LeakLock could leak or expose keys itself? Please see [SECURITY.md](SECURITY.md) instead of opening a public issue.
