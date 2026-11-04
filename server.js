require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

/* Saves logins to a file next to this one, so you stay connected after a restart. */
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
class FileStore extends session.Store {
  constructor() {
    super();
    try { this.data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')); } catch { this.data = {}; }
  }
  save() {
    try { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(this.data), { mode: 0o600 }); } catch (e) { console.error('Could not save sessions:', e.message); }
  }
  get(sid, cb) {
    const s = this.data[sid];
    if (s && s.cookie?.expires && new Date(s.cookie.expires) < new Date()) { delete this.data[sid]; this.save(); return cb(null, null); }
    cb(null, s || null);
  }
  set(sid, sess, cb) { this.data[sid] = sess; this.save(); cb && cb(null); }
  destroy(sid, cb) { delete this.data[sid]; this.save(); cb && cb(null); }
  touch(sid, sess, cb) { if (this.data[sid]) { this.data[sid].cookie = sess.cookie; this.save(); } cb && cb(null); }
}

// A secret that stays the same between restarts (so the login cookie keeps working).
function sessionSecret() {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET !== 'change-me-to-a-long-random-string') return process.env.SESSION_SECRET;
  const file = path.join(__dirname, '.session-secret');
  try { return fs.readFileSync(file, 'utf8').trim(); } catch {}
  const s = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(file, s, { mode: 0o600 }); } catch {}
  return s;
}

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = `${BASE_URL}/auth/google/callback`;
const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/classroom.courses.readonly',
  'https://www.googleapis.com/auth/classroom.coursework.me.readonly',
].join(' ');
const CLASSROOM = 'https://classroom.googleapis.com/v1';

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(
  session({
    secret: sessionSecret(),
    store: new FileStore(),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: BASE_URL.startsWith('https'),
      maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    },
  })
);
app.use(express.static(path.join(__dirname, 'public')));

/* ------------------------------------------------------------------ */
/*  Safety: only let the server fetch real public websites             */
/* ------------------------------------------------------------------ */
const dns = require('dns').promises;
const net = require('net');
function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
    return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}
async function safeFetch(url, opts) {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new Error('Links must start with https://');
  const addrs = await dns.lookup(u.hostname, { all: true }).catch(() => { throw new Error(`Couldn't find the website ${u.hostname}. Check the link.`); });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) throw new Error('That address isn\'t allowed.');
  return fetch(u, { ...opts, redirect: 'error', signal: AbortSignal.timeout(15000) });
}

/* ------------------------------------------------------------------ */
/*  Status                                                             */
/* ------------------------------------------------------------------ */

app.get('/api/status', (req, res) => {
  res.json({
    googleConfigured: Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
    google: Boolean(req.session.google),
    moodle: req.session.moodle
      ? { sitename: req.session.moodle.sitename, siteUrl: req.session.moodle.siteUrl }
      : null,
    canvas: req.session.canvas ? { sitename: req.session.canvas.sitename } : null,
    blackboard: req.session.blackboard ? { sitename: req.session.blackboard.sitename } : null,
  });
});

app.post('/api/disconnect/:provider', (req, res) => {
  const { provider } = req.params;
  if (['google', 'moodle', 'canvas', 'blackboard'].includes(provider)) delete req.session[provider];
  res.json({ ok: true });
});

/* ------------------------------------------------------------------ */
/*  Google Classroom                                                   */
/* ------------------------------------------------------------------ */

app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res
      .status(500)
      .send('Google sign-in is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env (see README).');
  }
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: GOOGLE_SCOPES,
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true',
    state,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`/?error=${encodeURIComponent(error)}`);
  if (!state || state !== req.session.oauthState) return res.status(400).send('Invalid sign-in state. Please try again.');
  delete req.session.oauthState;

  try {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });
    const t = await r.json();
    if (!r.ok) throw new Error(t.error_description || t.error || 'Token exchange failed');
    req.session.google = {
      access_token: t.access_token,
      refresh_token: t.refresh_token,
      expires_at: Date.now() + t.expires_in * 1000,
    };
    res.redirect('/');
  } catch (e) {
    res.redirect(`/?error=${encodeURIComponent(e.message)}`);
  }
});

async function getGoogleToken(req) {
  const g = req.session.google;
  if (!g) return null;
  if (Date.now() < g.expires_at - 60_000) return g.access_token;
  if (!g.refresh_token) {
    delete req.session.google;
    return null;
  }
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: g.refresh_token,
      grant_type: 'refresh_token',
    }),
  });
  const t = await r.json();
  if (!r.ok) {
    delete req.session.google;
    return null;
  }
  g.access_token = t.access_token;
  g.expires_at = Date.now() + t.expires_in * 1000;
  return g.access_token;
}

async function googleGet(token, url) {
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`Google Classroom ${r.status}: ${await r.text()}`);
  return r.json();
}

async function googleGetAll(token, url, key) {
  const items = [];
  let pageToken;
  do {
    const u = new URL(url);
    if (pageToken) u.searchParams.set('pageToken', pageToken);
    const data = await googleGet(token, u);
    items.push(...(data[key] || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return items;
}

// Classroom gives due dates as separate UTC date + time objects.
function classroomDue(d, t) {
  if (!d) return null;
  return new Date(Date.UTC(d.year, d.month - 1, d.day, t?.hours || 0, t?.minutes || 0)).toISOString();
}

app.get('/api/google/assignments', async (req, res) => {
  try {
    const token = await getGoogleToken(req);
    if (!token) return res.status(401).json({ error: 'not_connected' });

    const courses = await googleGetAll(
      token,
      `${CLASSROOM}/courses?studentId=me&courseStates=ACTIVE&pageSize=100`,
      'courses'
    );

    const perCourse = await Promise.all(
      courses.map(async (course) => {
        const [work, subs] = await Promise.all([
          googleGetAll(token, `${CLASSROOM}/courses/${course.id}/courseWork?courseWorkStates=PUBLISHED&pageSize=100`, 'courseWork').catch(() => []),
          googleGetAll(token, `${CLASSROOM}/courses/${course.id}/courseWork/-/studentSubmissions?userId=me&pageSize=100`, 'studentSubmissions').catch(() => []),
        ]);
        const subByWork = Object.fromEntries(subs.map((s) => [s.courseWorkId, s]));
        return work.map((w) => {
          const sub = subByWork[w.id];
          const done = sub && (sub.state === 'TURNED_IN' || sub.state === 'RETURNED');
          return {
            id: `gc-${w.id}`,
            source: 'google',
            title: w.title,
            course: course.name,
            due: classroomDue(w.dueDate, w.dueTime),
            url: w.alternateLink,
            type: (w.workType || 'ASSIGNMENT').toLowerCase().replace(/_/g, ' '),
            submitted: Boolean(done),
          };
        });
      })
    );

    res.json({ items: perCourse.flat() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ------------------------------------------------------------------ */
/*  Moodle                                                             */
/* ------------------------------------------------------------------ */

function normalizeSiteUrl(url) {
  url = String(url || '').trim();
  if (!url) throw new Error('Enter your Moodle site address');
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  const u = new URL(url);
  // Strip trailing /login/... or /my/ etc. — keep the Moodle root path
  return (u.origin + u.pathname.replace(/\/(login|my|course|mod)\b.*$/, '')).replace(/\/$/, '');
}

async function moodleCall(siteUrl, token, wsfunction, params = {}) {
  // Put the format in the URL too: some Moodle sites ignore it in the body and reply in XML.
  const query = new URLSearchParams({ wstoken: token, wsfunction, moodlewsrestformat: 'json' });
  const body = new URLSearchParams({ wstoken: token, wsfunction, moodlewsrestformat: 'json', ...params });
  const r = await safeFetch(`${siteUrl}/webservice/rest/server.php?${query}`, { method: 'POST', body });
  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    // Moodle replied in XML or HTML — pull out its error message if there is one.
    const msg = (text.match(/<MESSAGE>([\s\S]*?)<\/MESSAGE>/i) || [])[1];
    if (msg) throw new Error(`Moodle says: ${decodeEntities(msg.trim())}`);
    throw new Error(`Moodle sent an unexpected reply (HTTP ${r.status}). Check the site address and token.`);
  }
  if (data && data.exception) throw new Error(`Moodle says: ${data.message || data.errorcode}`);
  return data;
}

app.post('/api/moodle/connect', async (req, res) => {
  try {
    let { siteUrl, username, password, token } = req.body || {};
    siteUrl = normalizeSiteUrl(siteUrl);

    if (!token) {
      if (!username || !password) return res.status(400).json({ error: 'Enter your username and password, or a token' });
      // Same login the official Moodle mobile app uses. The password is used once and never stored.
      const r = await safeFetch(`${siteUrl}/login/token.php`, {
        method: 'POST',
        body: new URLSearchParams({ username, password, service: 'moodle_mobile_app' }),
      });
      const d = await r.json().catch(() => ({}));
      if (!d.token) {
        return res.status(400).json({
          error: d.error || 'Could not log in. If your school uses single sign-on, use a security key token instead.',
        });
      }
      token = d.token;
    }

    const info = await moodleCall(siteUrl, token, 'core_webservice_get_site_info');
    req.session.moodle = { siteUrl, token, sitename: info.sitename, userid: info.userid };
    res.json({ ok: true, sitename: info.sitename });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ---- Moodle via calendar export link (works with single sign-on) ---- */

function checkCalendarUrl(raw) {
  let u;
  try { u = new URL(String(raw || '').trim()); } catch { throw new Error('That doesn\'t look like a link. Copy the whole calendar URL from Moodle.'); }
  if (u.protocol !== 'https:' || !u.pathname.endsWith('/calendar/export_execute.php')) {
    throw new Error('That isn\'t a Moodle calendar link. It should contain "calendar/export_execute.php".');
  }
  return u;
}

function parseIcs(text) {
  const lines = text.replace(/\r\n/g, '\n').replace(/\n[ \t]/g, '').split('\n');
  const events = [];
  let cur = null;
  for (const line of lines) {
    if (line === 'BEGIN:VEVENT') { cur = {}; continue; }
    if (line === 'END:VEVENT') { if (cur) events.push(cur); cur = null; continue; }
    if (!cur) continue;
    const i = line.indexOf(':');
    if (i < 0) continue;
    const name = line.slice(0, i).split(';')[0].toUpperCase();
    cur[name] = line.slice(i + 1).replace(/\\n/gi, '\n').replace(/\\([,;\\])/g, '$1');
  }
  return events;
}

function icsDate(v) {
  if (!v) return null;
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?/);
  if (!m) return null;
  const [, y, mo, d, h = '23', mi = '59', s = '00', z] = m;
  const date = z
    ? new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s))
    : new Date(+y, +mo - 1, +d, +h, +mi, +s);
  return date.toISOString();
}

async function getIcs(u, name) {
  const r = await safeFetch(u);
  const text = await r.text();
  if (!r.ok || !text.includes('BEGIN:VCALENDAR')) {
    throw new Error(`${name} didn't send a calendar. Get a fresh calendar link from ${name} and try again.`);
  }
  return parseIcs(text);
}

async function fetchMoodleCalendar(calendarUrl) {
  const u = checkCalendarUrl(calendarUrl);
  const base = u.href.replace(/\/calendar\/export_execute\.php.*$/, '');
  const events = await getIcs(u, 'Moodle');
  return events.map((e) => {
    const eventId = (e.UID || '').split('@')[0];
    const ts = e.DTSTART ? Math.floor(new Date(icsDate(e.DTSTART)).getTime() / 1000) : '';
    return {
      id: `md-${e.UID || e.SUMMARY + e.DTSTART}`,
      source: 'moodle',
      title: (e.SUMMARY || 'Untitled').replace(/ is due$/i, ''),
      course: e.CATEGORIES || '',
      due: icsDate(e.DTSTART),
      // Opens the day in Moodle's calendar, where the event has a "Go to activity" button to submit.
      url: e.URL || (/^\d+$/.test(eventId)
        ? `${base}/calendar/view.php?view=day&time=${ts}#event_${eventId}`
        : `${base}/calendar/view.php?view=upcoming`),
      type: /is due$/i.test(e.SUMMARY || '') ? 'assignment' : 'event',
      submitted: false,
    };
  });
}

/* ---- Canvas via calendar feed link ---- */

function checkCanvasUrl(raw) {
  let u;
  try { u = new URL(String(raw || '').trim()); } catch { throw new Error('That doesn\'t look like a link. Copy the whole Calendar Feed link from Canvas.'); }
  if (u.protocol !== 'https:' || !/^\/feeds\/calendars\/.+\.ics$/.test(u.pathname)) {
    throw new Error('That isn\'t a Canvas calendar feed. It should contain "/feeds/calendars/" and end in ".ics".');
  }
  return u;
}

async function fetchCanvasCalendar(feedUrl) {
  const u = checkCanvasUrl(feedUrl);
  const events = await getIcs(u, 'Canvas');
  return events.map((e) => {
    // Canvas titles look like "Essay 2 [ENG 101]" — split out the course name.
    const m = (e.SUMMARY || '').match(/^(.*?)\s*\[([^\]]+)\]\s*$/);
    const title = m ? m[1] : e.SUMMARY || 'Untitled';
    const course = m ? m[2] : '';
    const assignmentId = ((e.UID || '').match(/assignment-(\d+)/) || [])[1];
    const courseId = ((e.URL || '').match(/course_(\d+)/) || [])[1];
    const isAssignment = /assignment/.test(e.UID || '');
    return {
      id: `cv-${e.UID || e.SUMMARY + e.DTSTART}`,
      source: 'canvas',
      title,
      course,
      due: icsDate(e.DTSTART),
      url: assignmentId && courseId
        ? `${u.origin}/courses/${courseId}/assignments/${assignmentId}`
        : e.URL || `${u.origin}/calendar`,
      type: isAssignment ? 'assignment' : 'event',
      submitted: false,
    };
  });
}

/* ---- Blackboard via "External Calendar Link" ---- */

function checkBlackboardUrl(raw) {
  let u;
  try { u = new URL(String(raw || '').trim()); } catch { throw new Error('That doesn\'t look like a link. Copy the whole External Calendar Link from Blackboard.'); }
  if (u.protocol !== 'https:' || !/calendarfeed/i.test(u.pathname) || !/\.ics$/i.test(u.pathname)) {
    throw new Error('That isn\'t a Blackboard calendar link. It should contain "calendarFeed" and end in ".ics".');
  }
  return u;
}

async function fetchBlackboardCalendar(feedUrl) {
  const u = checkBlackboardUrl(feedUrl);
  const events = await getIcs(u, 'Blackboard');
  return events.map((e) => {
    const summary = e.SUMMARY || 'Untitled';
    const due = /^due:\s*/i.test(summary);
    // Course name is usually in CATEGORIES or LOCATION; otherwise the first line of the description.
    const course = e.CATEGORIES || e.LOCATION || (e.DESCRIPTION || '').split('\n')[0].slice(0, 80);
    return {
      id: `bb-${e.UID || summary + e.DTSTART}`,
      source: 'blackboard',
      title: summary.replace(/^due:\s*/i, ''),
      course,
      due: icsDate(e.DTSTART),
      url: e.URL || `${u.origin}/ultra/calendar`,
      type: due || /assignment|quiz|test|exam|due/i.test(summary + ' ' + (e.DESCRIPTION || '')) ? 'assignment' : 'event',
      submitted: false,
    };
  });
}

/* ---- Connect / load routes for the calendar-link sites (Canvas, Blackboard) ---- */

const FEEDS = { canvas: fetchCanvasCalendar, blackboard: fetchBlackboardCalendar };

for (const [name, fetchFeed] of Object.entries(FEEDS)) {
  app.post(`/api/${name}/connect`, async (req, res) => {
    try {
      const { calendarUrl } = req.body || {};
      const items = await fetchFeed(calendarUrl);
      const host = new URL(calendarUrl.trim()).hostname;
      req.session[name] = { calendarUrl: calendarUrl.trim(), sitename: host };
      res.json({ ok: true, sitename: host, count: items.length });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.get(`/api/${name}/assignments`, async (req, res) => {
    try {
      const c = req.session[name];
      if (!c) return res.status(401).json({ error: 'not_connected' });
      res.json({ items: await fetchFeed(c.calendarUrl) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

app.post('/api/moodle/connect-calendar', async (req, res) => {
  try {
    const { calendarUrl } = req.body || {};
    const items = await fetchMoodleCalendar(calendarUrl);
    const host = new URL(calendarUrl.trim()).hostname;
    req.session.moodle = { calendarUrl: calendarUrl.trim(), sitename: host };
    res.json({ ok: true, sitename: host, count: items.length });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/moodle/assignments', async (req, res) => {
  try {
    const m = req.session.moodle;
    if (!m) return res.status(401).json({ error: 'not_connected' });
    if (m.calendarUrl) return res.json({ items: await fetchMoodleCalendar(m.calendarUrl) });

    const now = Math.floor(Date.now() / 1000);
    const events = [];
    let aftereventid;
    // This is the same data as Moodle's "Timeline" block: everything you still need to act on.
    for (let page = 0; page < 10; page++) {
      const params = {
        timesortfrom: String(now - 30 * 86400),
        timesortto: String(now + 180 * 86400),
        limitnum: '50',
      };
      if (aftereventid) params.aftereventid = String(aftereventid);
      const d = await moodleCall(m.siteUrl, m.token, 'core_calendar_get_action_events_by_timesort', params);
      const batch = d.events || [];
      events.push(...batch);
      if (batch.length < 50) break;
      aftereventid = batch[batch.length - 1].id;
    }

    const items = events.map((e) => ({
      id: `md-${e.id}`,
      source: 'moodle',
      title: decodeEntities(e.activityname || e.name),
      course: decodeEntities(e.course?.fullname || ''),
      due: new Date(e.timesort * 1000).toISOString(),
      url: e.url || e.action?.url || m.siteUrl,
      type: e.modulename || 'activity',
      submitted: false, // action events only include things still to do
    }));

    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'");
}

app.listen(PORT, () => console.log(`DueBoard running at ${BASE_URL}`));
