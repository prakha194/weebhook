# Webhooker Backend (Node.js + Express)

## What this does
- Create projects with password + api key
- Store project config in Firestore
- Proxy GET/POST to all stored URLs for a project and return array of results
- Basic in-memory rate limiting per api key

## Setup (local)
1. `git clone <repo>`
2. `cd <repo>`
3. `npm install`
4. Create a `.env` file (use `.env.example`) and set:
   - FIREBASE_PROJECT_ID
   - FIREBASE_CLIENT_EMAIL
   - FIREBASE_PRIVATE_KEY (use \\n for newlines if required)
   - PORT (optional)
5. `npm run dev` (requires nodemon) or `npm start`

## Firebase service account
Create a service account JSON in Firebase console (Project Settings -> Service Accounts). You only need `project_id`, `client_email`, and `private_key`. Do NOT commit the JSON to the repo. Place values into Render environment variables.

## Deploy to Render (summary)
1. Create a new Web Service on Render and connect to your GitHub repo.
2. Set the environment variables in the Render dashboard (use values from `.env.example`).
3. Start command: `npm start`
4. After deploy, test: `GET https://<your-render-url>/health`

## Notes
- This starter uses in-memory rate limiting. For production use Redis or another central store.
- Never commit credentials to GitHub.