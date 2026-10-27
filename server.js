require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// Logging a user in must NOT happen on the shared admin client: signInWithPassword
// would switch that client to the user's token and row-level security would then
// block visit reads/writes. Use a throwaway client for every sign-in.
const authClient = () => createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const ADMIN_KEY = process.env.ADMIN_KEY || '';
const ALLOW_SIGNUP = process.env.ALLOW_SIGNUP === '1';
const BUCKET = 'avatars'; // Supabase Storage bucket (must be PUBLIC)

/* ========================= HELPERS ========================= */
const FIELD_LIMITS = {
  name: 80, profession: 120, bio: 1000, location: 120, website: 200,
  email: 120, phone: 40, company: 120, interests: 200, available: 200,
  instagram: 300, facebook: 300, tiktok: 300, linkedin: 300,
  business_start: 7, businesses: 1000
};
const SOCIALS = ['instagram', 'facebook', 'tiktok', 'linkedin'];
const EDITABLE = Object.keys(FIELD_LIMITS);
const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,29}$/;

/* ========================= SERIES (Essential / Signature) ========================= */
const SERIES = ['essential', 'signature'];
const isSig = (p) => !!p && p.series === 'signature';
const cssHref = (p) => (isSig(p) ? '/signature.css' : '/style.css');
const themeColor = (p) => (isSig(p) ? '#0c0c0c' : '#090b09');

function fmtStart(v) {
  const m = /^(\d{4})-(\d{2})$/.exec(v || '');
  if (!m) return null;
  const label = new Date(Date.UTC(+m[1], +m[2] - 1, 1))
    .toLocaleString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' });
  const now = new Date();
  const months = Math.max(0, (now.getUTCFullYear() - +m[1]) * 12 + (now.getUTCMonth() - (+m[2] - 1)));
  const y = Math.floor(months / 12);
  const span = y >= 1 ? `${y} year${y > 1 ? 's' : ''} in business`
    : months >= 1 ? ${months} month${months > 1 ? 's' : ''} in business : '';
  return { label, span };
}

/* ---- visit tracking (Signature only) ---- */
const recentVisits = new Map();
const BOT_RE = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|curl|wget|headless/i;
function recordVisit(req, p) {
  if (req.method !== 'GET' || !isSig(p)) return;
  const ua = req.get('user-agent') || '';
  if (!ua || BOT_RE.test(ua)) return;
  const key = req.ip + '|' + ua + '|' + p.user_id;
  const now = Date.now();
  if (now - (recentVisits.get(key) || 0) < 10 * 60e3) return; // same device within 10 min counts once
  recentVisits.set(key, now);
  supabase.from('profile_visits').insert({ user_id: p.user_id })
    .then(({ error }) => { if (error) console.error('visit log failed:', error.message); });
}
setInterval(() => {
  const cutoff = Date.now() - 10 * 60e3;
  for (const [k, t] of recentVisits) if (t < cutoff) recentVisits.delete(k);
}, 10 * 60e3).unref();

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

function cleanUrl(v) {
  v = String(v || '').trim();
  if (!v || /^n\/?a$/i.test(v)) return '';
  if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
  try {
    const u = new URL(v);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    return u.toString();
  } catch {
    return '';
  }
}

function cleanProfile(input) {
  const out = {};
  for (const k of EDITABLE) {
    if (input[k] === undefined) continue;
    let v = String(input[k] ?? '').trim().slice(0, FIELD_LIMITS[k]);
    if (SOCIALS.includes(k) || k === 'website') v = cleanUrl(v);
    if (k === 'email' && v && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
      throw new Error('Email address looks invalid.');
    }
    if (k === 'businesses') {
      const seen = new Set();
      v = String(input[k] ?? '').split(/\r?\n/)
        .map((x) => x.trim().replace(/\s+/g, ' ').slice(0, 60))
        .filter((x) => x && !seen.has(x.toLowerCase()) && seen.add(x.toLowerCase()))
        .slice(0, 😎.join('\n');
    }
    if (k === 'business_start' && v) {
      const m = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(v);
      if (!m || +m[1] < 1900 || +m[1] > new Date().getUTCFullYear()) {
        throw new Error('Business start must be a valid month and year.');
      }
    }
    out[k] = v;
  }
  if (typeof input.show_visits === 'boolean') out.show_visits = input.show_visits;
  return out;
}

/* ========================= COOKIES / AUTH ========================= */
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) {
      try {
        out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
      } catch { /* ignore bad cookie */ }
    }
  });
  return out;
}
const COOKIE_AGE = 60 * 60 * 24 * 365; // keep owners logged in for about a year

function cookieStr(name, value, req, maxAge) {
  const secure = req && req.secure ? '; Secure' : '';
  return name + '=' + encodeURIComponent(value) +
    '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + maxAge + secure;
}
function setAuthCookie(res, req, session) {
  const cookies = [cookieStr('sid', session.access_token, req, COOKIE_AGE)];
  if (session.refresh_token) cookies.push(cookieStr('rid', session.refresh_token, req, COOKIE_AGE));
  res.setHeader('Set-Cookie', cookies);
}

function clearAuthCookie(res, req) {
  res.setHeader('Set-Cookie', [cookieStr('sid', '', req, 0), cookieStr('rid', '', req, 0)]);
}

/* Finds the logged-in user. If the short login token has expired, it quietly
   gets a new one using the long-lasting refresh cookie. */
async function resolveUser(req, res) {
  const cookies = parseCookies(req);
  if (cookies.sid) {
    const { data: { user }, error } = await supabase.auth.getUser(cookies.sid);
    if (!error && user) return user;
  }
  if (cookies.rid) {
    const tmp = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SECRET_KEY,
      { auth: { autoRefreshToken: false, persistSession: false } }
    );
    const { data, error } = await tmp.auth.refreshSession({ refresh_token: cookies.rid });
    if (!error && data && data.session && data.user) {
      setAuthCookie(res, req, data.session);
      return data.user;
    }
  }
  return null;
}

async function auth(req, res, next) {
  try {
    const user = await resolveUser(req, res);
    if (!user) return res.status(401).json({ error: 'Please log in.' });
    req.authUser = user;
    const { data: profile, error: profileError } = await supabase
      .from('profiles').select('*').eq('user_id', user.id).maybeSingle();
    if (profileError) {
      console.error(profileError);
      return res.status(500).json({ error: 'Could not load profile.' });
    }
    req.profile = profile;
    next();
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Please log in.' });
  }
}
async function getViewerId(req, res) {
  try {
    const user = await resolveUser(req, res);
    return user ? user.id : null;
  } catch {
    return null;
  }
}

/* ========================= ADMIN ========================= */
function adminOnly(req, res, next) {
  const key = String(req.headers['x-admin-key'] || '');
  if (!ADMIN_KEY) return res.status(403).json({ error: 'Admin features are disabled.' });
  const ok = key.length === ADMIN_KEY.length &&
    crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_KEY));
  if (!ok) return res.status(403).json({ error: 'Invalid admin key.' });
  next();
}

/* ========================= LOGIN THROTTLE ========================= */
const attempts = new Map();
function throttled(key) {
  const now = Date.now();
  const rec = (attempts.get(key) || []).filter((t) => now - t < 15 * 60e3);
  attempts.set(key, rec);
  return rec.length >= 10;
}
function noteAttempt(key) {
  attempts.set(key, [...(attempts.get(key) || []), Date.now()]);
}

/* ========================= PROFILE HELPERS ========================= */
async function getProfileByUserId(userId) {
  const { data, error } = await supabase
    .from('profiles').select('*').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data;
}

async function getProfileByUsername(username) {
  const { data, error } = await supabase
    .from('profiles').select('*').eq('username', username).maybeSingle();
  if (error) throw error;
  return data;
}

/* ========================= USER CREATION ========================= */
async function createUser(username, password, name, series) {
  username = String(username || '').toLowerCase().trim();
  password = String(password || '');

  if (!USERNAME_RE.test(username)) {
    throw new Error('Username must be 3-30 characters: letters, numbers, - or _.');
  }
  if (password.length < 😎 {
    throw new Error('Password must be at least 8 characters.');
  }
  const existing = await getProfileByUsername(username);
  if (existing) throw new Error('That username is taken.');

  const authEmail = ${username}@users.yournfc.local;
  const { data, error } = await supabase.auth.admin.createUser({
    email: authEmail,
    password,
    email_confirm: true,
    user_metadata: { username }
  });
  if (error) {
    console.error(error);
    throw new Error(error.message);
  }
  const user = data.user;
  if (!user) throw new Error('Could not create user.');

  const { error: profileError } = await supabase.from('profiles').insert({
    user_id: user.id,
    username,
    name: String(name || username).slice(0, 80),
    series: SERIES.includes(series) ? series : 'essential'
  });
  if (profileError) {
    await supabase.auth.admin.deleteUser(user.id);
    console.error(profileError);
    throw new Error('Account was not created because the profile could not be saved.');
  }
  return { id: user.id, username };
}

/* ========================= EXPRESS ========================= */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.json({ limit: '50kb' }));
// Dashboard: pick the stylesheet by the owner's series before the page loads (no colour flash).
app.get('/edit', async (req, res) => {
  try {
    const user = await resolveUser(req, res);
    const p = user ? await getProfileByUserId(user.id) : null;
    const html = fs.readFileSync(path.join(__dirname, 'public', 'edit.html'), 'utf8')
      .replace('href="/style.css"', href="${cssHref(p)}")
      .replace('content="#0c0c0c"', content="${themeColor(p)}");
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(html);
  } catch (err) {
    console.error(err);
    res.sendFile(path.join(__dirname, 'public', 'edit.html'));
  }
});
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], index: false }));

app.get('/', (req, res) => res.redirect('/login'));

/* ========================= PUBLIC VCARD ========================= */
const vEsc = (s) =>
  String(s || '').replace(/\\/g, '\\\\').replace(/\r?\n/g, '\\n').replace(/([,;])/g, '\\$1');

app.get('/u/:username.vcf', async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const p = await getProfileByUsername(username);
    if (!p) return res.status(404).send('Not found');

    const vcard = [
      'BEGIN:VCARD', 'VERSION:3.0',
      'FN:' + vEsc(p.name || username),
      'TITLE:' + vEsc(p.profession),
      'ORG:' + vEsc(p.company),
      'TEL:' + vEsc(p.phone),
      'EMAIL:' + vEsc(p.email),
      'URL:' + vEsc(p.website),
      'NOTE:' + vEsc(p.bio),
      'END:VCARD'
    ].join('\r\n');

    res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
    res.setHeader('Content-Disposition', attachment; filename="${username}.vcf");
    res.send(vcard);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

/* ========================= PUBLIC PROFILE ========================= */
const AVATAR_GOLD =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 120'%3E%3Crect width='120' height='120' fill='%23222419'/%3E%3Ccircle cx='60' cy='43' r='22' fill='%23c9a227'/%3E%3Cpath d='M18 120c3-29 19-43 42-43s39 14 42 43' fill='%23c9a227'/%3E%3C/svg%3E";
const AVATAR_GREY =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 120'%3E%3Crect width='120' height='120' fill='%231f1f1f'/%3E%3Ccircle cx='60' cy='43' r='22' fill='%23777777'/%3E%3Cpath d='M18 120c3-29 19-43 42-43s39 14 42 43' fill='%23777777'/%3E%3C/svg%3E";

const SOCIAL_META = {
  instagram: ['Instagram', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>'],
  facebook: ['Facebook', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg>'],
  tiktok: ['TikTok', '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-label="TikTok"><path fill="currentColor" d="M12.525.02c1.31-.02 2.61-.01 3.91-.02.08 1.53.63 3.09 1.75 4.17 1.12 1.11 2.7 1.62 4.24 1.79v4.03c-1.44-.05-2.89-.35-4.2-.97-.57-.26-1.1-.59-1.62-.93-.01 2.92.01 5.84-.02 8.75-.08 1.4-.54 2.79-1.35 3.94-1.31 1.92-3.58 3.17-5.91 3.21-1.43.08-2.86-.31-4.08-1.03-2.02-1.19-3.44-3.37-3.65-5.71-.02-.5-.03-1-.01-1.49.18-1.9 1.12-3.72 2.58-4.96 1.66-1.44 3.98-2.13 6.15-1.72.02 1.48-.04 2.96-.04 4.44-.99-.32-2.15-.23-3.02.37-.63.41-1.11 1.04-1.36 1.75-.21.51-.15 1.07-.14 1.61.24 1.64 1.82 3.02 3.5 2.87 1.12-.01 2.19-.66 2.77-1.61.19-.33.4-.67.41-1.06.1-1.79.06-3.57.07-5.36.01-4.03-.01-8.05.02-12.07z"/></svg>'],
  linkedin: ['LinkedIn', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg>'],
};

function renderProfile(p, username, isOwner, visitCount) {
  const socials =
    SOCIALS.filter((k) => p[k]).map((k) => {
      const handle = p[k].replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, '');
      return `
        <a class="social" href="${esc(p[k])}" target="_blank" rel="noopener noreferrer">
          <span class="social-icon ${k}">${SOCIAL_META[k][1]}</span>
          <span><strong>${SOCIAL_META[k][0]}</strong><small>${esc(handle)}</small></span>
        </a>`;
    }).join('') || '<p class="edit-hint">Social links have not been added yet.</p>';

  const nz = (v) => esc(v || 'Not added');
  const siteHref = p.website ? esc(p.website) : '';
  // Only full Supabase URLs are used; old local filenames fall back to the default avatar.
  const sig = isSig(p);
  const DEFAULT_AVATAR = AVATAR_GOLD;
  const photo = p.photo && /^https?:\/\//.test(p.photo) ? esc(p.photo) : DEFAULT_AVATAR;
  const start = sig ? fmtStart(p.business_start) : null;
  const bizList = sig ? String(p.businesses || '').split('\n').filter(Boolean) : [];
  const showCount = sig && Number.isInteger(visitCount);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="${themeColor(p)}">
  <title>${esc(p.name || 'Digital Profile')} | YourNFC.</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="${cssHref(p)}">
  <style>
    .social-icon svg{width:22px;height:22px;display:block}
${sig ?     .social-icon.instagram,.social-icon.facebook,.social-icon.tiktok,.social-icon.linkedin{background:#262626;color:#e4e4e4} : `    .social-icon.instagram{background:linear-gradient(45deg,#bc1888,#dc2743,#f09433);color:#fff}
    .social-icon.facebook{background:#1877f2;color:#fff}
    .social-icon.tiktok{background:#000;color:#fff;box-shadow:2px 2px 0 #fe2c55,-2px -2px 0 #25f4ee}
    .social-icon.linkedin{background:#0a66c2;color:#fff}
   .cover{background:url('/cover.jpg') center / cover no-repeat}
   .cover-label{text-shadow:0 1px 8px #000}`}
  </style>
</head>
<body>
<header class="topbar">
  <div class="brand-container"><div class="brand">Your<span>NFC.</span></div></div>
 ${isOwner
  ? '<a class="btn btn-primary" href="/edit">Edit my profile</a>'
  : '<div class="top-note">TAP. CONNECT. BEYOND</div>'
 }
</header>
<main class="page">
  <article class="profile">
    <div class="cover"><span class="cover-label">Your digital identity</span></div>
    <div class="intro">
      <img class="avatar" alt="Profile photo" src="${photo}" onerror="this.onerror=null;this.src='${DEFAULT_AVATAR}'">
      <h1 class="name">${nz(p.name)}</h1>
      <p class="profession">${nz(p.profession)}${sig && p.company ? ' · ' + esc(p.company) : ''}</p>
      ${(start || showCount) ? <div class="chips">${start ? `<span class="chip">In business since ${esc(start.label)}${start.span ? ' · ' + start.span : ''}</span> : ''}${showCount ? <span class="chip">${visitCount.toLocaleString('en-US')} profile visit${visitCount === 1 ? '' : 's'}</span> : ''}</div>` : ''}
      <div class="bio">${nz(p.bio)}</div>
      <div class="meta">
        <span>⌖ ${esc(p.location || 'Location not added')}</span>
        <span>↗ ${siteHref
          ? <a href="${siteHref}" target="_blank" rel="noopener noreferrer">${esc(p.website.replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, ''))}</a>
          : 'Website not added'}</span>
      </div>
      <div class="contact-row">
        <a class="btn btn-primary" href="${p.email ? 'mailto:' + esc(p.email) : '#'}">${p.email ? 'Contact me' : 'Contact info'}</a>
        <a class="btn btn-secondary" href="/u/${esc(username)}.vcf">Save contact</a>
      </div>
    </div>
  </article>

  <section class="section">
    <h2>Find me online</h2>
    <div class="links">${socials}</div>
  </section>

  ${bizList.length ? `<section class="section">
    <h2>Businesses</h2>
    <div class="tags">${bizList.map((b) => <span class="tag">${esc(b)}</span>).join('')}</div>
  </section>
` : ''}
  <section class="section">
    <h2>My Info</h2>
    <div class="details">
      <div class="detail"><label>Profession</label><div>${nz(p.profession)}</div></div>
      <div class="detail"><label>Company / School</label><div>${nz(p.company)}</div></div>
      <div class="detail"><label>Email</label><div>${nz(p.email)}</div></div>
      <div class="detail"><label>Phone</label><div>${nz(p.phone)}</div></div>
      ${start ? <div class="detail"><label>In business since</label><div>${esc(start.label)}</div></div> : ''}
      <div class="detail"><label>Interests</label><div>${nz(p.interests)}</div></div>
      <div class="detail"><label>Available for</label><div>${nz(p.available)}</div></div>
    </div>
  </section>

  <footer>POWERED BY <span style="color:var(--accent-light)">YourNFC</span> · TAP. CONNECT. BEYOND${isOwner ? '' : ' · <a href="/login" style="color:inherit">Owner Login</a>'}</footer>
</main>
</body>
</html>`;
}

app.get('/u/:username', async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const p = await getProfileByUsername(username);
    if (!p) return res.status(404).send('Profile not found');
    const viewerId = await getViewerId(req, res);
    const isOwner = !!viewerId && viewerId === p.user_id;
    res.setHeader('Cache-Control', isOwner ? 'no-store' : 'no-cache');
    if (!isOwner) recordVisit(req, p);
    let visitCount = null;
    if (isSig(p) && p.show_visits !== false) {
      const { count, error } = await supabase.from('profile_visits')
        .select('id', { count: 'exact', head: true }).eq('user_id', p.user_id);
      if (!error && Number.isInteger(count)) visitCount = count;
    }
    res.send(renderProfile(p, username, isOwner, visitCount));
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

/* ========================= LOGIN / SIGNUP ========================= */
app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const key = req.ip + '|' + username;

    if (throttled(key)) {
      return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
    }
    const profile = await getProfileByUsername(username);
    if (!profile) {
      noteAttempt(key);
      return res.status(401).json({ error: 'Wrong username or password.' });
    }
    const { data, error } = await authClient().auth.signInWithPassword({
      email: ${username}@users.yournfc.local,
      password
    });
    if (error || !data.session) {
      noteAttempt(key);
      return res.status(401).json({ error: 'Wrong username or password.' });
    }
    setAuthCookie(res, req, data.session);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    if (!ALLOW_SIGNUP) {
      return res.status(403).json({ error: 'Sign-ups are closed. Ask YourNFC for an account.' });
    }
    const u = await createUser(req.body.username, req.body.password, req.body.name);
    const { data, error } = await authClient().auth.signInWithPassword({
      email: ${u.username}@users.yournfc.local,
      password: String(req.body.password || '')
    });
    if (error || !data.session) {
      return res.status(500).json({ error: 'Account created, but automatic login failed.' });
    }
    setAuthCookie(res, req, data.session);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/config', (req, res) => res.json({ signup: ALLOW_SIGNUP }));

app.post('/api/logout', (req, res) => {
  clearAuthCookie(res, req);
  res.json({ ok: true });
});

/* ========================= CURRENT USER ========================= */
app.get('/api/me', auth, async (req, res) => {
  try {
    const p = await getProfileByUserId(req.authUser.id);
    res.json({ username: p?.username || '', profile: p });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load profile.' });
  }
});

app.put('/api/me', auth, async (req, res) => {
  try {
    const data = cleanProfile(req.body || {});
    if (!isSig(req.profile)) { delete data.business_start; delete data.businesses; delete data.show_visits; }
    if (Object.keys(data).length) {
      const { error } = await supabase
        .from('profiles').update(data).eq('user_id', req.authUser.id);
      if (error) throw error;
    }
    const profile = await getProfileByUserId(req.authUser.id);
    res.json({ ok: true, profile });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

/* ========================= VISIT RECORDS (Signature) ========================= */
app.get('/api/me/stats', auth, async (req, res) => {
  try {
    if (!isSig(req.profile)) {
      return res.status(403).json({ error: 'Visit records are part of the Signature series.' });
    }
    const uid = req.authUser.id;
    const since = (days) => new Date(Date.now() - days * 864e5).toISOString();
    const count = (days) => {
      let q = supabase.from('profile_visits').select('id', { count: 'exact', head: true }).eq('user_id', uid);
      if (days) q = q.gte('visited_at', since(days));
      return q;
    };
    const [total, week, month, recent] = await Promise.all([
      count(), count(7), count(30),
      supabase.from('profile_visits').select('visited_at').eq('user_id', uid)
        .order('visited_at', { ascending: false }).limit(15)
    ]);
    for (const r of [total, week, month, recent]) if (r.error) throw r.error;
    res.json({
      total: total.count || 0, last7: week.count || 0, last30: month.count || 0,
      recent: (recent.data || []).map((v) => v.visited_at)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load visit records. Did you run migration-signature.sql?' });
  }
});

/* ========================= PHOTO UPLOAD (Supabase Storage) ========================= */
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    cb(
      EXT[file.mimetype] ? null : new Error('Photo must be a JPG, PNG or WebP image.'),
      !!EXT[file.mimetype]
    );
  }
});

// Deletes an old photo from Supabase Storage, given its public URL.
async function removePhotoFile(photo) {
  try {
    if (!photo || !/^https?:\/\//.test(photo)) return;
    const marker = /storage/v1/object/public/${BUCKET}/;
    const i = photo.indexOf(marker);
    if (i === -1) return;
    const filePath = decodeURIComponent(photo.slice(i + marker.length).split('?')[0]);
    await supabase.storage.from(BUCKET).remove([filePath]);
  } catch (e) {
    console.error(e);
  }
}

app.post('/api/me/photo', auth, (req, res) => {
  upload.single('photo')(req, res, async (err) => {
    try {
      if (err) {
        return res.status(400).json({
          error: err.code === 'LIMIT_FILE_SIZE' ? 'Photo must be under 3 MB.' : err.message
        });
      }
      if (!req.file) return res.status(400).json({ error: 'No photo received.' });

      const old = req.profile?.photo || '';
      const filePath = ${req.authUser.id}/${crypto.randomBytes(12).toString('hex')}${EXT[req.file.mimetype]};

      const { error: upErr } = await supabase.storage
        .from(BUCKET)
        .upload(filePath, req.file.buffer, { contentType: req.file.mimetype });
      if (upErr) throw upErr;

      const { data: pub } = supabase.storage.from(BUCKET).getPublicUrl(filePath);
      const photoUrl = pub.publicUrl;

      const { error } = await supabase
        .from('profiles').update({ photo: photoUrl }).eq('user_id', req.authUser.id);
      if (error) {
        await removePhotoFile(photoUrl);
        throw error;
      }
      await removePhotoFile(old);
      res.json({ ok: true, photo: photoUrl });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Could not save photo.' });
    }
  });
});

app.delete('/api/me/photo', auth, async (req, res) => {
  try {
    const old = req.profile?.photo || '';
    const { error } = await supabase
      .from('profiles').update({ photo: '' }).eq('user_id', req.authUser.id);
    if (error) throw error;
    await removePhotoFile(old);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not remove photo.' });
  }
});

/* ========================= PASSWORD ========================= */
app.post('/api/me/password', auth, async (req, res) => {
  try {
    const { current, next: newPassword } = req.body || {};
    const password = String(newPassword || '');
    if (password.length < 😎 {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    const username = req.profile?.username;
    if (!username) return res.status(400).json({ error: 'Account username is missing.' });

    const { error: loginError } = await authClient().auth.signInWithPassword({
      email: ${username}@users.yournfc.local,
      password: String(current || '')
    });
    if (loginError) return res.status(400).json({ error: 'Current password is wrong.' });

    const { error } = await supabase.auth.admin.updateUserById(req.authUser.id, { password });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not change password.' });
  }
});

/* ========================= ADMIN API ========================= */
app.get('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('username,name,series,created_at,updated_at')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load users.' });
  }
});

app.post('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const u = await createUser(req.body.username, req.body.password, req.body.name, req.body.series);
    res.json({ ok: true, ...u });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/admin/users/:username/password', adminOnly, async (req, res) => {
  try {
    const username = String(req.params.username || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    if (password.length < 😎 {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    const profile = await getProfileByUsername(username);
    if (!profile) return res.status(404).json({ error: 'No such user.' });

    const { error } = await supabase.auth.admin.updateUserById(profile.user_id, { password });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not change password.' });
  }
});

app.post('/api/admin/users/:username/series', adminOnly, async (req, res) => {
  try {
    const username = String(req.params.username || '').toLowerCase().trim();
    const series = String(req.body.series || '');
    if (!SERIES.includes(series)) return res.status(400).json({ error: 'Series must be essential or signature.' });
    const { data, error } = await supabase.from('profiles').update({ series }).eq('username', username).select('username');
    if (error) throw error;
    if (!data || !data.length) return res.status(404).json({ error: 'No such user.' });
    res.json({ ok: true, series });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not change series.' });
  }
});

app.delete('/api/admin/users/:username', adminOnly, async (req, res) => {
  try {
    const username = String(req.params.username || '').toLowerCase().trim();
    const profile = await getProfileByUsername(username);
    if (!profile) return res.status(404).json({ error: 'No such user.' });

    await removePhotoFile(profile.photo);
    const { error } = await supabase.auth.admin.deleteUser(profile.user_id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not delete user.' });
  }
});

/* ========================= PAGES ========================= */
const page = (f) => (req, res) => res.sendFile(path.join(__dirname, 'public', f));
app.get('/login', page('login.html'));
app.get('/admin', page('admin.html'));

/* ========================= ERROR HANDLER ========================= */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

/* ========================= START ========================= */
console.log('Supabase URL loaded:', !!process.env.SUPABASE_URL);
console.log('Supabase secret loaded:', !!process.env.SUPABASE_SECRET_KEY);

app.listen(PORT, () => {
  console.log(YourNFC running on http://localhost:${PORT});
});
