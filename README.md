# DueBoard

One page that shows every assignment from **Moodle** and **Google Classroom**, sorted by due date and grouped into Overdue / Today / Tomorrow / This week / Later.

## Run it

Needs Node.js 18 or newer.

```bash
npm install
cp .env.example .env      # then fill it in (see below)
npm start                 # → http://localhost:3000
```

## Set up Google Classroom (one time, ~10 minutes)

1. Go to <https://console.cloud.google.com/> and create a project.
2. **APIs & Services → Library** → enable **Google Classroom API**.
3. **APIs & Services → OAuth consent screen** → choose *External*, fill in the app name and your email, and add these scopes:
   - `.../auth/classroom.courses.readonly`
   - `.../auth/classroom.coursework.me.readonly`
   While the app is in *Testing*, add each student's Google account under **Test users**.
4. **APIs & Services → Credentials → Create credentials → OAuth client ID** → *Web application*.
   Add the authorized redirect URI: `http://localhost:3000/auth/google/callback`
   (use your real domain instead when you deploy, and update `BASE_URL` to match).
5. Copy the client ID and secret into `.env`.

> Some school Google Workspace accounts block third-party apps. If sign-in says the app is blocked, the school's Workspace admin has to allow it.

## Connect Moodle

No setup needed on your side — students enter their Moodle address plus username and password on the page. DueBoard exchanges those once for an access token (the same way the official Moodle mobile app logs in) and never stores the password.

- **Requirement:** the school's Moodle must allow the mobile app (if the Moodle app works for your school, DueBoard will too).
- **Single sign-on schools** (login through Microsoft/Google/university portal): username/password won't work. Instead, open Moodle → profile → **Preferences → Security keys**, copy the *Moodle mobile web service* key, and paste it using “use a token instead.”

Moodle items come from the same feed as Moodle's Timeline block: assignments, quizzes, forums and other activities that still need action, from 30 days ago to 6 months ahead.

## How it works

- `server.js` — Express server. Handles Google OAuth, the Moodle login, and calls both APIs server-side (Moodle doesn't allow direct browser calls), keeping tokens in the session rather than in the browser.
- `public/index.html` — the dashboard. Opened without the server running, it shows sample data so you can see the layout.
- "Mark done" checkmarks are saved in the browser. Classroom work you've turned in is marked done automatically.

## Deploying

Any Node host works (Render, Railway, Fly.io, a VPS). Set the four `.env` values as environment variables, set `BASE_URL` to your https address, and add `<BASE_URL>/auth/google/callback` as a redirect URI in Google Cloud. Sessions are kept in memory, so everyone reconnects after a restart — swap in a session store (e.g. `connect-redis`) if that matters.
