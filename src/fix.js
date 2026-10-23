// Turns a finding into a plain fix: what to do, and a prompt to paste into the AI builder
// (Lovable, Bolt, Cursor, v0) that made the app. Never includes the key itself.

const SERVER_ONLY = {
  critical: true,
  secret: true,
};

function article(word) {
  return /^[aeiou]/i.test(word) || /^(8|11|18|x[^a-z]|s3|r2)/i.test(word) ? 'an' : 'a';
}

function keyNoun(f) {
  const p = f.provider.replace(/ \(project .*\)$/, '');
  return /(key|token|secret|webhook)s?$/i.test(p) ? p : p + ' API key';
}

function apiName(f) {
  return f.provider.replace(/ (API key|key|token|secret key|secret).*$/i, '').trim() || 'this API';
}

/**
 * @param {object} f a merged finding from scanUrl / scanDir
 * @returns {{ steps: string[], prompt: string } | null}
 */
export function fixFor(f) {
  if (!SERVER_ONLY[f.severity]) return null;
  const name = apiName(f);
  const where = f.files?.length ? f.files.slice(0, 2).join(', ') : 'your frontend bundle';

  if (/service_role|Supabase secret/i.test(f.provider)) {
    return {
      steps: [
                'Find where the frontend uses it and switch that code to the anon key.',
        'Anything that truly needs admin rights moves into a Supabase Edge Function.',
        'Turn on Row Level Security for every table.',
        'Strongly recommended: rotate the key (Project Settings → API Keys), since it gives full database access.',
      ],
      prompt: `My app ships the Supabase service_role key to the browser (found in ${where}). Fix this without changing how the app works:\n1. Replace every frontend use of the service_role key with the anon key.\n2. Move any operation that genuinely needs admin rights into a Supabase Edge Function that reads SUPABASE_SERVICE_ROLE_KEY from its secrets, and call that function from the frontend instead.\n3. Make sure Row Level Security is enabled on every table, with policies that keep each user's existing access.\n4. Do not change any UI, routes or business logic. Show me the list of files you changed.`,
    };
  }

  const envName = (name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '') || 'API') + '_API_KEY';
  return {
    steps: [
      `Move the call to a server: create a small function (Supabase Edge Function, Netlify/Vercel function) that calls ${name}, and have the frontend call that function.`,
      `Store the key as a server secret (${envName}), never in frontend code or VITE_/NEXT_PUBLIC_ variables.`,
      'Republish and scan again to confirm the key is gone.',
      `Recommended: rotate the ${name} key too, since anyone may already have copied it while it was public.`,
    ],
    prompt: `My app exposes ${article(keyNoun(f))} ${keyNoun(f)} in the browser bundle (found in ${where}${f.host ? `, sent to ${f.host}` : ''}). Anyone can copy it. Fix this without changing how the app behaves:\n1. Create a server-side function (use a Supabase Edge Function if this project uses Supabase, otherwise a serverless function on our host) that makes the same ${name} request${f.host ? ` to ${f.host}` : ''}, reading the key from a secret named ${envName}.\n2. Replace the browser's direct call with a call to that function, passing the same inputs and returning the same response shape.\n3. Remove the key from all frontend code, .env files with VITE_ or NEXT_PUBLIC_ prefixes, and constants.\n4. Only allow requests from our own site and add a basic rate limit.\n5. Do not change any UI, routes or other logic. List every file you changed.\nI will set the ${envName} secret myself.`,
  };
}

export function withFixes(report) {
  for (const f of report.findings) {
    const fix = fixFor(f);
    if (fix) f.fix = fix;
  }
  return report;
}
