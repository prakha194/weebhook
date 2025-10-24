require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const admin = require('firebase-admin');

// ----- Validate env -----
const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
let privateKey = process.env.FIREBASE_PRIVATE_KEY || null;

if (!projectId || !clientEmail || !privateKey) {
  console.error('ERROR: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY must be set in environment.');
  process.exit(1);
}

// Fix newline escapes if required
privateKey = privateKey.replace(/\\n/g, '\n');

// ----- Firestore init -----
admin.initializeApp({
  credential: admin.credential.cert({
    projectId,
    clientEmail,
    privateKey,
  }),
});

const db = admin.firestore();
const projectsColl = db.collection('projects');

// ----- App setup -----
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 8080;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '60', 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const EXTERNAL_TIMEOUT_MS = parseInt(process.env.EXTERNAL_TIMEOUT_MS || '10000', 10);

// In-memory rate limiter per apiKey (basic). Persistent limiter (Redis) recommended for production.
const rateMap = new Map();
function checkRateLimit(apiKey) {
  if (!apiKey) return false;
  const now = Date.now();
  const entry = rateMap.get(apiKey);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateMap.set(apiKey, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count < RATE_LIMIT_MAX) {
    entry.count += 1;
    rateMap.set(apiKey, entry);
    return true;
  }
  return false;
}

// ----- Helpers -----
async function createProjectRecord(name, password) {
  const projectId = uuidv4();
  const apiKey = uuidv4().replace(/-/g, '');
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);
  const doc = {
    name: name || 'project-' + projectId.slice(0, 6),
    api_key: apiKey,
    password_hash: passwordHash,
    urls: [],
    created_at: admin.firestore.FieldValue.serverTimestamp(),
  };
  await projectsColl.doc(projectId).set(doc);
  return { projectId, apiKey };
}

async function getProject(projectId) {
  const snap = await projectsColl.doc(projectId).get();
  if (!snap.exists) return null;
  return { id: snap.id, ...snap.data() };
}

// Filter headers to forward to target (drop hop-by-hop and sensitive headers)
function filterForwardHeaders(headers) {
  const out = {};
  const blacklist = ['host', 'connection', 'content-length', 'accept-encoding'];
  for (const k of Object.keys(headers)) {
    if (blacklist.includes(k.toLowerCase())) continue;
    if (k.toLowerCase().startsWith('x-forwarded-')) continue;
    if (k.toLowerCase() === 'x-api-key') continue; // don't forward the caller's API key
    out[k] = headers[k];
  }
  return out;
}

// ----- Routes -----
// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Create project
app.post('/projects', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!password || password.length < 4) {
      return res.status(400).json({ error: 'password required (min length 4)' });
    }
    const { projectId, apiKey } = await createProjectRecord(name, password);
    return res.json({ projectId, apiKey });
  } catch (err) {
    console.error('create project error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Unlock project (enter password) -> returns project config (without hash)
app.post('/projects/:id/unlock', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'password required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });
    const { password_hash, ...rest } = project;
    return res.json(rest);
  } catch (err) {
    console.error('unlock project error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Add URL (requires password)
app.post('/projects/:id/urls', async (req, res) => {
  try {
    const id = req.params.id;
    const { password, url } = req.body;
    if (!password || !url) return res.status(400).json({ error: 'password and url required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });
    await projectsColl.doc(id).update({
      urls: admin.firestore.FieldValue.arrayUnion(url),
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('add url error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Remove URL (requires password)
app.delete('/projects/:id/urls', async (req, res) => {
  try {
    const id = req.params.id;
    const { password, url } = req.body;
    if (!password || !url) return res.status(400).json({ error: 'password and url required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });
    await projectsColl.doc(id).update({
      urls: admin.firestore.FieldValue.arrayRemove(url),
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('remove url error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Delete project (requires password)
app.delete('/projects/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'password required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });
    await projectsColl.doc(id).delete();
    return res.json({ ok: true });
  } catch (err) {
    console.error('delete project error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Update project name (requires password)
app.patch('/projects/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const { password, name } = req.body;
    if (!password || !name) return res.status(400).json({ error: 'password and name required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });
    await projectsColl.doc(id).update({ name });
    return res.json({ ok: true });
  } catch (err) {
    console.error('update project error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Regenerate API key (requires password)
app.post('/projects/:id/regenerate-key', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'password required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });
    const newKey = uuidv4().replace(/-/g, '');
    await projectsColl.doc(id).update({ api_key: newKey });
    return res.json({ apiKey: newKey });
  } catch (err) {
    console.error('regenerate key error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// ----- Proxy endpoint -----
// Accepts GET and POST. Requires apiKey via header 'x-api-key' or query 'api_key'
app.all('/api/:projectId', async (req, res) => {
  try {
    const projectId = req.params.projectId;
    const apiKey = (req.headers['x-api-key'] || req.query.api_key || '').toString();
    if (!apiKey) return res.status(401).json({ error: 'api_key required' });

    // Rate limit
    if (!checkRateLimit(apiKey)) {
      return res.status(429).json({ error: 'rate limit exceeded' });
    }

    const project = await getProject(projectId);
    if (!project) return res.status(404).json({ error: 'project not found' });
    if (apiKey !== project.api_key) return res.status(403).json({ error: 'invalid api key' });

    const urls = project.urls || [];

    // Build requests
    const requests = urls.map((url) => {
      let finalUrl = url;
      if (req.method === 'GET' && req.query && req.query.query) {
        finalUrl = url.replace(/\{query\}/g, encodeURIComponent(req.query.query));
      }

      const axiosOpts = {
        url: finalUrl,
        method: req.method,
        timeout: EXTERNAL_TIMEOUT_MS,
        headers: {
          ...filterForwardHeaders(req.headers),
        },
      };

      if (req.method === 'POST') {
        axiosOpts.data = req.body;
      }

      return axios(axiosOpts)
        .then((r) => ({ url: finalUrl, status: 'success', statusCode: r.status, data: r.data }))
        .catch((e) => {
          let msg = e.message;
          if (e.response) msg = `${e.response.status} ${e.response.statusText}`;
          return { url: finalUrl, status: 'error', message: msg };
        });
    });

    const results = await Promise.all(requests);
    return res.json(results);
  } catch (err) {
    console.error('proxy error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Webhooker backend listening on port ${PORT}`);
});