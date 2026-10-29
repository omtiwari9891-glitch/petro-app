# PetroFlow Pro — Updated Version

## Files
- `package.json` — Node.js dependencies and start command.
- `server.js` — Express API, SQLite database, authentication, shift sales, inventory and analytics.
- `public/index.html` — Responsive dashboard and frontend.

## Run locally
1. Install Node.js 18 or newer.
2. Open a terminal in this folder and run `npm install`.
3. Set a strong JWT secret (at least 32 characters), then start the app.

Linux/macOS:
```bash
JWT_SECRET="replace-with-a-long-random-secret-at-least-32-chars" npm start
```

PowerShell:
```powershell
$env:JWT_SECRET = "replace-with-a-long-random-secret-at-least-32-chars"
npm start
```

Open `http://localhost:3000`.

## Deploying on Render
- Build command: `npm install`
- Start command: `npm start`
- Add an environment variable named `JWT_SECRET` with a long random secret.
- Add a persistent disk and set `DB_PATH` to a file path on that disk (for example `/var/data/database.sqlite`). Without persistent storage, SQLite data may be lost during redeploys/restarts depending on your host setup.

## Important notes
- Existing SQLite databases are retained; the unused `plainPassword` column may remain in an older database but the updated app no longer writes to it or returns passwords. For stronger data hygiene, back up the database and migrate/remove old plaintext password data.
- Existing accounts should continue to work if their password hashes were created with bcryptjs. A username collision during registration is reported rather than silently changing the username.
- This is a starter ERP, not a full accounting system. Revenue is not profit. Add a delivery ledger, expenses, purchase costs, audit log, backups and role-based access before relying on it for business-critical accounting.
- Tailwind is loaded from its CDN for easy setup. For a hardened production build, compile Tailwind locally and configure a strict Content Security Policy.
- If the existing app has been publicly deployed with the old hard-coded JWT secret, set a new environment secret. This will invalidate old login tokens, so users will need to sign in again.
