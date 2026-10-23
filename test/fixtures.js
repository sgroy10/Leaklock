// Fake keys, assembled at runtime so no real-looking secret sits in the repo
// (and GitHub push protection does not flag the test suite).
let seed = 42;
const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
const pick = (set, n) => Array.from({ length: n }, () => set[Math.floor(rnd() * set.length)]).join('');
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const URLSAFE = ALNUM + '_-';
const HEX = '0123456789abcdef';
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload) => [b64url({ alg: 'HS256', typ: 'JWT' }), b64url(payload), pick(URLSAFE, 43)].join('.');

export const KEYS = {
  openai: 'sk-' + 'proj-' + pick(URLSAFE, 40) + 'T3Blbk' + 'FJ' + pick(URLSAFE, 40),
  openaiLegacy: 'sk-' + pick(ALNUM, 48),
  anthropic: 'sk-' + 'ant-api03-' + pick(URLSAFE, 93),
  openrouter: 'sk-' + 'or-v1-' + pick(HEX, 64),
  groq: 'gsk' + '_' + pick(ALNUM, 52),
  stripeLive: 'sk' + '_live_' + pick(ALNUM, 99),
  stripePk: 'pk' + '_live_' + pick(ALNUM, 99),
  github: 'ghp' + '_' + pick(ALNUM, 36),
  aws: 'AKIA' + pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16),
  google: 'AIza' + pick(URLSAFE, 35),
  googleFirebase: 'AIza' + pick(URLSAFE, 35),
  supabaseService: jwt({ iss: 'supabase', ref: 'abcdefghijklmnop', role: 'service_role', iat: 1700000000, exp: 2000000000 }),
  supabaseAnon: jwt({ iss: 'supabase', ref: 'abcdefghijklmnop', role: 'anon', iat: 1700000000, exp: 2000000000 }),
  randomJwt: jwt({ sub: '123', name: 'demo user' }),
  sendgrid: 'SG' + '.' + pick(URLSAFE, 22) + '.' + pick(URLSAFE, 43),
};

export const VITE_BUNDLE = `
const ai=new OpenAI({apiKey:"${KEYS.openai}",dangerouslyAllowBrowser:!0});fetch("https://api.openai.com/v1/chat/completions");
const sb=createClient("https://abcdefghijklmnop.supabase.co","${KEYS.supabaseAnon}");
const admin=createClient("https://abcdefghijklmnop.supabase.co","${KEYS.supabaseService}");
const stripe=Stripe("${KEYS.stripePk}");const s2="${KEYS.stripeLive}";
const firebaseConfig={apiKey:"${KEYS.googleFirebase}",authDomain:"demo.firebaseapp.com",projectId:"demo"};
const t="${KEYS.randomJwt}";
const placeholder="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
`;
