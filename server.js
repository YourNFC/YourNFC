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

const ADMIN_KEY = process.env.ADMIN_KEY || '';
const ALLOW_SIGNUP = process.env.ALLOW_SIGNUP === '1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ========================= HELPERS ========================= */
const FIELD_LIMITS = {
  name: 80, profession: 120, bio: 1000, location: 120, website: 200,
  email: 120, phone: 40, company: 120, interests: 200, available: 200,
  instagram: 300, facebook: 300, tiktok: 300, linkedin: 300
};
const SOCIALS = ['instagram', 'facebook', 'tiktok', 'linkedin'];
const EDITABLE = Object.keys(FIELD_LIMITS);
const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,29}$/;

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
    out[k] = v;
  }
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

  return '${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}';
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
async function getViewerId(req, res){
  try {
    const user = await
      resolveUser(req, res);
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
async function createUser(username, password, name) {
  username = String(username || '').toLowerCase().trim();
  password = String(password || '');

  if (!USERNAME_RE.test(username)) {
    throw new Error('Username must be 3-30 characters: letters, numbers, - or _.');
  }
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters.');
  }
  const existing = await getProfileByUsername(username);
  if (existing) throw new Error('That username is taken.');

  const authEmail = `${username}@users.yournfc.local`;
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
    name: String(name || username).slice(0, 80)
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
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '1h', index: false, dotfiles: 'deny' }));
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
    res.setHeader('Content-Disposition', `attachment; filename="${username}.vcf"`);
    res.send(vcard);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

/* ========================= PUBLIC PROFILE ========================= */
const DEFAULT_AVATAR =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 120'%3E%3Crect width='120' height='120' fill='%23222419'/%3E%3Ccircle cx='60' cy='43' r='22' fill='%23c9a227'/%3E%3Cpath d='M18 120c3-29 19-43 42-43s39 14 42 43' fill='%23c9a227'/%3E%3C/svg%3E";

const SOCIAL_META = {
  instagram: ['Instagram', '◎'],
  facebook: ['Facebook', 'f'],
  tiktok: ['TikTok', '♪'],
  linkedin: ['LinkedIn', 'in']
};

function renderProfile(p, username, isOwner) {
  const socials =
    SOCIALS.filter((k) => p[k]).map((k) => {
      const handle = p[k].replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, '');
      return `
        <a class="social" href="${esc(p[k])}" target="_blank" rel="noopener noreferrer">
          <span class="social-icon">${SOCIAL_META[k][1]}</span>
          <span><strong>${SOCIAL_META[k][0]}</strong><small>${esc(handle)}</small></span>
        </a>`;
    }).join('') || '<p class="edit-hint">Social links have not been added yet.</p>';

  const nz = (v) => esc(v || 'Not added');
  const siteHref = p.website ? esc(p.website) : '';
  const photo = p.photo ? `/uploads/${esc(p.photo)}` : DEFAULT_AVATAR;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#090b09">
  <title>${esc(p.name || 'Digital Profile')} | YourNFC</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="topbar">
  <div class="brand-container"><div class="brand">Your<span>NFC</span></div></div>
 ${isOwner
  ? '<a class="btn btn-primary" href="/edit">Edit my profile</a>'
  : '<div class="top-note">TAP. CONNECT. BEYOND</div>'

 }
</header>
<main class="page">
  <article class="profile">
    <div class="cover"><span class="cover-label">Your digital identity</span></div>
    <div class="intro">
      <img class="avatar" alt="Profile photo" src="${photo}">
      <h1 class="name">${nz(p.name)}</h1>
      <p class="profession">${nz(p.profession)}</p>
      <div class="bio">${nz(p.bio)}</div>
      <div class="meta">
        <span>⌖ ${esc(p.location || 'Location not added')}</span>
        <span>↗ ${siteHref
          ? `<a href="${siteHref}" target="_blank" rel="noopener noreferrer">${esc(p.website.replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, ''))}</a>`
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

  <section class="section">
    <h2>A little about me</h2>
    <div class="details">
      <div class="detail"><label>Profession</label><div>${nz(p.profession)}</div></div>
      <div class="detail"><label>Company / School</label><div>${nz(p.company)}</div></div>
      <div class="detail"><label>Email</label><div>${nz(p.email)}</div></div>
      <div class="detail"><label>Phone</label><div>${nz(p.phone)}</div></div>
      <div class="detail"><label>Interests</label><div>${nz(p.interests)}</div></div>
      <div class="detail"><label>Available for</label><div>${nz(p.available)}</div></div>
    </div>
  </section>

  <footer>POWERED BY <span style="color:var(--gold-light)">YourNFC</span> · TAP. CONNECT. BEYOND${isOwner ? '' : ' . <a href="/login" style="color:inherit"Owner Login</a>'}</footer>
</main>
</body>
</html>`;
}

app.get('/u/:username', async (req, res) => {
  try {
    const username = req.params.username.toLowerCase().trim();
    const p = await getProfileByUsername(username);
    if (!p) return res.status(404).send('Profile not found');
    const viewerId = await  getViewerId(req, res);
    const isOwner = !!viewerId && viewerId === p.user_id;
    res.setHeader('Cache-Control', isOwner ? 'no-store':'no-cache');
    res.send(renderProfile(p, username, isOwner)); // can be used to edit info (if you are the owner of the acc line 331-332)
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
    const { data, error } = await supabase.auth.signInWithPassword({
      email: `${username}@users.yournfc.local`,
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
    const { data, error } = await supabase.auth.signInWithPassword({
      email: `${u.username}@users.yournfc.local`,
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

/* ========================= PHOTO UPLOAD ========================= */
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) =>
      cb(null, crypto.randomBytes(12).toString('hex') + (EXT[file.mimetype] || ''))
  }),
  limits: { fileSize: 3 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    cb(
      EXT[file.mimetype] ? null : new Error('Photo must be a JPG, PNG or WebP image.'),
      !!EXT[file.mimetype]
    );
  }
});

function removePhotoFile(name) {
  if (name && /^[a-f0-9]+\.(jpg|png|webp)$/.test(name)) {
    fs.unlink(path.join(UPLOAD_DIR, name), () => {});
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
      const { error } = await supabase
        .from('profiles').update({ photo: req.file.filename }).eq('user_id', req.authUser.id);
      if (error) {
        removePhotoFile(req.file.filename);
        throw error;
      }
      removePhotoFile(old);
      res.json({ ok: true, photo: req.file.filename });
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
    removePhotoFile(old);
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
    if (password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    const username = req.profile?.username;
    if (!username) return res.status(400).json({ error: 'Account username is missing.' });

    const { error: loginError } = await supabase.auth.signInWithPassword({
      email: `${username}@users.yournfc.local`,
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
      .select('username,name,created_at,updated_at')
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
    const u = await createUser(req.body.username, req.body.password, req.body.name);
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
    if (password.length < 8) {
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

app.delete('/api/admin/users/:username', adminOnly, async (req, res) => {
  try {
    const username = String(req.params.username || '').toLowerCase().trim();
    const profile = await getProfileByUsername(username);
    if (!profile) return res.status(404).json({ error: 'No such user.' });

    removePhotoFile(profile.photo);
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
app.get('/edit', page('edit.html'));
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
  console.log(`YourNFC running on http://localhost:${PORT}`);
});
