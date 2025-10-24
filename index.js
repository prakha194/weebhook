javascript
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const admin = require('firebase-admin');

// ----- Firestore init -----
// This code reads the service account from env vars. You can also mount a service account JSON file
const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
let privateKey = process.env.FIREBASE_PRIVATE_KEY || null;

if (!projectId || !clientEmail || !privateKey) {
  console.error('FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY must be set.');
  process.exit(1);
}

// Handle escaped newlines
privateKey = privateKey.replace(/\\n/g, '\n');

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
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 8080;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '60');
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000');
const EXTERNAL_TIMEOUT_MS = parseInt(process.env.EXTERNAL_TIMEOUT_MS || '10000');

// Simple in-memory rate limiter per apiKey (basic)
// Structure: { apiKey: { count: number, windowStart: timestamp } }
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

// Get project details (requires project password in body)
app.post('/projects/:id/unlock', async (req, res) => {
  const id = req.params.id;
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });
  const project = await getProject(id);
  if (!project) return res.status(404).json({ error: 'not found' });
  const ok = await bcrypt.compare(password, project.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid password' });
  // Return project config without sensitive hash
  const { password_hash, ...rest } = project;
  return res.json(rest);
});

// Add URL
app.post('/projects/:id/urls', async (req, res) => {
  try {
    const id = req.params.id;
    const { password, url } = req.body;
    if (!password || !url) return res.status(400).json({ error: 'password and url required' });
    const project = await getProject(id);
    if (!project) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, project.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid password' });

    const updated = await projectsColl.doc(id).update({
      urls: admin.firestore.FieldValue.arrayUnion(url),
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('add url error', err);
    return res.status(500).json({ error: 'internal' });
  }
});

// Remove URL by exact string
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

// Delete project
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

// Update project name
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
    const apiKey = req.headers['x-api-key'] || req.query.api_key;
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
      // Replace {query} placeholders
      let finalUrl = url;
      if (req.method === 'GET' && req.query && req.query.query) {
        finalUrl = url.replace(/\{query\}/g, encodeURIComponent(req.query.query));
      }

      const axiosOpts = {
        url: finalUrl,
        method: req.method,
        timeout: EXTERNAL_TIMEOUT_MS,
        headers: {
          // pass along user-sent headers for POST/GET except host/connection
          ...filterForwardHeaders(req.headers),
          // Do not forward x-api-key header to target unless explicitly desired
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

// ----- Helpers to filter headers -----
function filterForwardHeaders(headers) {
  const out = {};
  const blacklist = ['host', 'connection', 'content-length'];
  for (const k of Object.keys(headers)) {
    if (blacklist.includes(k.toLowerCase())) continue;
    // Skip express internal headers
    if (k.toLowerCase().startsWith('x-forwarded-')) continue;
    out[k] = headers[k];
  }
  return out;
}

// Start
app.listen(PORT, () => {
  console.log(`Webhooker backend listening on port ${PORT}`);
});
