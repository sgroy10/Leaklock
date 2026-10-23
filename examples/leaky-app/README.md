# Leaky demo app

A tiny built app with leaks planted on purpose, so you can see LeakLock work without scanning anyone's real site. The keys are fake.

```bash
npx leaklock scan examples/leaky-app/dist --fix
```

It contains:

- a key for an API with **no recognizable prefix** (a plain 32-character hex string, like many smaller AI APIs use), sent as `Authorization: Bearer`. Pattern-based scanners can't see it; LeakLock catches it by how it's used.
- a key sent in an `x-api-key` header to a made-up API.
- a Supabase `anon` key, which is public by design and reported as safe.
