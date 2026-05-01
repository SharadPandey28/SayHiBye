# DH Secure Chat — Deployment Guide
## 100% Free Stack: Render + MongoDB Atlas + Upstash Redis + Cloudflare

---

## Project Structure

```
dh-secure-chat/
├── src/
│   ├── server.js              ← main entry point
│   ├── config/
│   │   ├── index.js           ← all env config
│   │   └── logger.js          ← pino logger
│   ├── db/
│   │   ├── mongo.js           ← MongoDB models + connection
│   │   └── redis.js           ← Redis connection + rate limiter
│   ├── middleware/
│   │   └── auth.js            ← JWT middleware
│   ├── routes/
│   │   ├── auth.js            ← /api/auth/register, /login, /me
│   │   └── admin.js           ← /api/admin/stats, /users, /rooms
│   └── socket/
│       ├── handlers.js        ← all Socket.io event handlers
│       └── store.js           ← in-memory live room state
├── public/
│   ├── index.html             ← chat UI
│   ├── admin.html             ← admin dashboard
│   └── crypto/
│       └── provider.js        ← CryptoProvider abstraction
├── .env.example               ← copy to .env and fill in values
├── render.yaml                ← Render auto-deploy config
├── Dockerfile                 ← optional Docker deployment
└── .github/workflows/
    └── deploy.yml             ← GitHub Actions CI/CD
```

---

## Step 1 — MongoDB Atlas (free M0 cluster)

1. Go to https://cloud.mongodb.com and sign up (free)
2. Create a new project → **Build a Database** → **M0 Free**
3. Choose a region (pick closest to your Render region: Oregon/US)
4. Create a database user:
   - Username: `dhchat_user`
   - Password: generate a strong one — **save it**
5. Network Access → **Add IP Address** → `0.0.0.0/0` (allow all — Render uses dynamic IPs)
6. Click **Connect** → **Drivers** → copy the connection string:
   ```
   mongodb+srv://dhchat_user:<password>@cluster0.xxxxx.mongodb.net/dhsecurechat
   ```
   Replace `<password>` with your actual password.

---

## Step 2 — Upstash Redis (free serverless Redis)

1. Go to https://console.upstash.com and sign up (free, no credit card)
2. **Create Database** → name it `dh-secure-chat` → region: US-East-1
3. Go to the database → **Details** tab → copy the **Redis URL**:
   ```
   redis://default:xxxxx@us1-xxxx.upstash.io:6379
   ```
   > Note: Upstash free tier = 10,000 commands/day. For a new app this is plenty.

---

## Step 3 — GitHub Repository

1. Create a new repo at https://github.com/new
   - Name: `dh-secure-chat`
   - Private or public — your choice
2. Push your code:
   ```bash
   cd dh-secure-chat
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/dh-secure-chat.git
   git push -u origin main
   ```

---

## Step 4 — Render (free Node.js hosting)

1. Go to https://render.com and sign up with GitHub (free)
2. **New** → **Web Service** → connect your `dh-secure-chat` repo
3. Settings:
   - **Name**: `dh-secure-chat`
   - **Region**: Oregon (US West)
   - **Branch**: `main`
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free
4. **Environment Variables** — add these in Render dashboard:

   | Key | Value |
   |-----|-------|
   | `NODE_ENV` | `production` |
   | `PORT` | `3001` |
   | `MONGO_URI` | your Atlas connection string |
   | `REDIS_URL` | your Upstash Redis URL |
   | `JWT_SECRET` | run: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
   | `ADMIN_PASSWORD` | choose a strong password |
   | `ALLOWED_ORIGIN` | `https://your-app.onrender.com` (update after deploy) |

5. Click **Create Web Service** — first deploy takes ~3 minutes
6. Your app will be live at: `https://dh-secure-chat.onrender.com`

   > ⚠️ Free Render apps sleep after 15min of inactivity. First request takes ~30s cold start.
   > Fix: set up UptimeRobot to ping `/health` every 14 minutes.

---

## Step 5 — GitHub Actions (auto-deploy on push)

1. In Render dashboard → your service → **Settings** → **Deploy Hook** → copy the URL
2. In GitHub repo → **Settings** → **Secrets and variables** → **Actions** → **New secret**:
   - Name: `RENDER_DEPLOY_HOOK`
   - Value: the URL you copied
3. Now every `git push` to `main` will auto-deploy.

---

## Step 6 — Custom Domain + Free SSL via Cloudflare (optional but recommended)

1. Buy a domain (~$8-15/yr from Namecheap or Cloudflare Registrar)
2. Sign up at https://cloudflare.com (free)
3. Add your domain to Cloudflare → update nameservers at your registrar
4. In Cloudflare DNS → add a CNAME record:
   - Name: `@` (or `www`)
   - Target: `dh-secure-chat.onrender.com`
   - Proxy: ✅ Enabled (orange cloud)
5. In Render → your service → **Custom Domains** → add your domain
6. SSL is automatic via Cloudflare (free)
7. Update `ALLOWED_ORIGIN` env var in Render to your custom domain:
   ```
   https://yourdomain.com
   ```

---

## Step 7 — UptimeRobot (free monitoring + prevents Render sleep)

1. Go to https://uptimerobot.com and sign up (free)
2. **Add New Monitor**:
   - Type: HTTP(S)
   - Name: `DH Secure Chat`
   - URL: `https://your-app.onrender.com/health`
   - Monitoring Interval: **5 minutes**
3. Add alert contact (email) for downtime notifications
4. This also prevents Render free tier cold starts by keeping the app warm

---

## Step 8 — First Login

After deploy, visit your app URL:

1. **Chat** (`/`): Register a new account → you're in
2. **Admin** (`/admin.html`):
   - Username: `admin`
   - Password: the `ADMIN_PASSWORD` you set in Render env vars
   - **Change this password immediately after first login**

---

## Local Development

```bash
# 1. Clone repo
git clone https://github.com/YOUR_USERNAME/dh-secure-chat.git
cd dh-secure-chat

# 2. Install deps
npm install

# 3. Setup env
cp .env.example .env
# Edit .env with your values (can use local MongoDB/Redis for dev)

# 4. Run dev server (with hot reload)
npm run dev

# 5. Open http://localhost:3001
```

For local MongoDB + Redis without cloud accounts:
```bash
# Install MongoDB locally
brew install mongodb-community  # macOS
# or use Docker:
docker run -d -p 27017:27017 mongo
docker run -d -p 6379:6379 redis

# Then in .env:
# MONGO_URI=mongodb://localhost:27017/dhsecurechat
# REDIS_URL=redis://localhost:6379
```

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `NODE_ENV` | Yes | `production` or `development` |
| `PORT` | Yes | Server port (Render sets this automatically) |
| `MONGO_URI` | Yes | MongoDB Atlas connection string |
| `REDIS_URL` | Yes | Upstash Redis URL |
| `JWT_SECRET` | Yes | 64-char random hex string |
| `ADMIN_PASSWORD` | Yes | Initial admin account password |
| `ALLOWED_ORIGIN` | Yes | Your frontend URL for CORS |

---

## Cost Summary

| Service | Cost | Limit |
|---------|------|-------|
| Render (web service) | Free | 750 hrs/mo, sleeps after 15min idle |
| MongoDB Atlas M0 | Free forever | 512MB storage |
| Upstash Redis | Free | 10,000 commands/day |
| Cloudflare | Free forever | Unlimited bandwidth |
| UptimeRobot | Free | 50 monitors, 5min intervals |
| **Total** | **$0/mo** | Domain ~$8/yr only |

---

## Upgrading When You Have Real Users

| What to upgrade | When | Cost |
|-----------------|------|------|
| Render Starter plan | >100 concurrent users | $7/mo (no sleep) |
| MongoDB Atlas M2 | >50,000 audit logs | $9/mo |
| Upstash Pro | >10k Redis cmds/day | $10/mo |
| **Total** | **When you need it** | **~$26/mo** |
